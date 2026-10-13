import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHmac} from 'node:crypto';
import net from 'node:net';
import {PassThrough} from 'node:stream';
import {makeServer} from '../server.mjs';
import {readConfig} from '../auth.mjs';
import {android013Signature,verifyAndroid013Headers} from '../android013.mjs';

const env={IB_MASTER_KEY:'a'.repeat(64),IB_DEVICE_ID:'ib-device-13',IB_SESSION_BYTE_CAP:'30720',IB_ANDROID013_COMPAT:'1'};
const cfg=readConfig(env);
const fakeLookup=async(host)=>host==='example.com'?[{address:'93.184.216.34',family:4}]:[{address:'127.0.0.1',family:4}];
const echoConnect=()=>{
  const s=new PassThrough();
  process.nextTick(()=>s.emit('connect'));
  return s;
};
function headers(time=String(Date.now()),nonce=randomBytes(16).toString('hex')){
  return {'X-IB-ID':cfg.device,'X-IB-TS':time,'X-IB-Nonce':nonce,'X-IB-MAC':android013Signature(cfg,cfg.device,time,nonce)};
}
async function withServer(body,opts={}) {
  const svr=makeServer(opts.noConfig?{IB_ANDROID013_COMPAT:'1'}:env,{android013Lookup:fakeLookup,android013Connect:echoConnect});
  const sockets=new Set();svr.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise(ok=>svr.listen(0,'127.0.0.1',ok));
  try{return await body(svr.address().port);}finally{
    for(const s of sockets)s.destroy();
    await new Promise(ok=>svr.close(ok));
  }
}
function requestWs(port,auth={},path='/tunnel'){
  return new Promise((resolve,reject)=>{
    const sock=net.connect(port,'127.0.0.1');let buffer=Buffer.alloc(0);
    const timer=setTimeout(()=>{sock.destroy();reject(new Error('handshake timeout'));},3000);
    sock.once('error',e=>{clearTimeout(timer);reject(e);});
    sock.on('data',chunk=>{
      buffer=Buffer.concat([buffer,chunk]);const end=buffer.indexOf('\r\n\r\n');if(end<0)return;
      clearTimeout(timer);sock.removeAllListeners('data');
      resolve({socket:sock,status:buffer.toString('latin1',0,end).split('\r\n')[0],left:buffer.subarray(end+4)});
    });
    sock.on('connect',()=>{
      const line=[`GET ${path} HTTP/1.1`,`Host: 127.0.0.1:${port}`,'Upgrade: websocket','Connection: Upgrade','Sec-WebSocket-Key: '+randomBytes(16).toString('base64'),'Sec-WebSocket-Version: 13',...Object.entries(auth).map(([k,v])=>`${k}: ${v}`),'',''].join('\r\n');
      sock.write(line);
    });
  });
}
function maskedFrame(data,opcode=1){
  const body=Buffer.isBuffer(data)?data:Buffer.from(JSON.stringify(data));
  const mask=randomBytes(4),size=body.length;
  const h=size<126?Buffer.from([0x80|opcode,0x80|size]):Buffer.from([0x80|opcode,0xfe,(size>>8)&0xff,size&0xff]);
  const x=Buffer.from(body);for(let i=0;i<size;i++)x[i]^=mask[i&3];
  return Buffer.concat([h,mask,x]);
}
function oneFrame(buf){
  if(buf.length<2)return;
  let n=buf[1]&0x7f,p=2;
  if(n===126){if(buf.length<4)return;n=buf.readUInt16BE(2);p=4;}
  else if(n===127){if(buf.length<10)return;n=Number(buf.readBigUInt64BE(2));p=10;}
  if(buf.length<p+n)return;
  const op=buf[0]&15,bytes=buf.subarray(p,p+n);
  return {opcode:op,value:op===1?JSON.parse(bytes.toString()):bytes,left:buf.subarray(p+n)};
}
function nextFrame(socket,initial=Buffer.alloc(0)){
  return new Promise((resolve,reject)=>{
    let buffer=Buffer.from(initial);
    const timer=setTimeout(()=>{clean();reject(new Error('frame timeout'));},3500);
    function clean(){clearTimeout(timer);socket.off('data',feed);}
    function feed(chunk){buffer=Buffer.concat([buffer,chunk]);const parsed=oneFrame(buffer);if(parsed){clean();resolve(parsed);}}
    socket.on('data',feed);feed(Buffer.alloc(0));
  });
}

test('Android 0.13 HMAC matches old Kotlin wire and rejects tampering',()=>{
  const h=headers();const normalized=Object.fromEntries(Object.entries(h).map(([k,v])=>[k.toLowerCase(),v]));
  assert.equal(verifyAndroid013Headers(cfg,normalized).ok,true);
  assert.equal(verifyAndroid013Headers(cfg,{...normalized,'x-ib-mac':'f'.repeat(64)}).ok,false);
  assert.equal(verifyAndroid013Headers(cfg,{...normalized,'x-ib-id':'another-device'}).ok,false);
  assert.equal(verifyAndroid013Headers(cfg,{...normalized,'x-ib-ts':String(Date.now()-120000)}).ok,false);
});

test('Kotlin and Node 0.13 key derivation agrees on a fixed cross-language vector',()=>{
  const expectedKey='47bb4a4c848b4e770db96245bc19e06bb0ca9fd2a6c94c96076a9c3c588e6c3d';
  const expectedMac='ac39a0592bf6b84417d27f7e0de190f52b6a5f05e020d32031ffe41fca1a9bd4';
  const testConfig={key:Buffer.from('aa'.repeat(32),'hex')};
  const derived=createHmac('sha256',testConfig.key).update('IB09-device:ib-device-13').digest('hex');
  assert.equal(derived,expectedKey);
  assert.equal(android013Signature(testConfig,'ib-device-13','1790000000000','0123456789abcdef0123456789abcdef'),expectedMac);
});

test('Android 0.13 upgrade succeeds, private host and port denied, DNS returns expected shape',async()=>{
  await withServer(async port=>{
    const auth=headers();const a=await requestWs(port,auth);assert.match(a.status,/101/);
    let p=nextFrame(a.socket,a.left);a.socket.write(maskedFrame({op:'dns',host:'example.com'}));
    let x=await p;assert.equal(x.value.op,'dns');assert.equal(x.value.host,'example.com');assert.equal(x.value.address,'93.184.216.34');
    p=nextFrame(a.socket);a.socket.write(maskedFrame({op:'connect',host:'127.0.0.1',port:443}));
    x=await p;assert.equal(x.value.op,'error');assert.equal(x.value.error,'destination_blocked');
    p=nextFrame(a.socket);a.socket.write(maskedFrame({op:'connect',host:'example.com',port:22}));
    x=await p;assert.equal(x.value.op,'error');assert.equal(x.value.error,'destination_blocked');
    p=nextFrame(a.socket);a.socket.write(maskedFrame({op:'balance'}));
    x=await p;assert.equal(x.value.error,'ib1_voucher_required');
    const duplicate=await requestWs(port,auth);assert.match(duplicate.status,/401/);duplicate.socket.destroy();a.socket.destroy();
  });
});

test('Android 0.13 voucher header is fail-closed until durable rights support exists',async()=>{
  await withServer(async port=>{
    const h={...headers(),'X-IB-Voucher':'IB1.madeup'};
    const a=await requestWs(port,h);assert.match(a.status,/503/);a.socket.destroy();
    const b=await requestWs(port,{'X-IB-ID':cfg.device});assert.match(b.status,/401/);b.socket.destroy();
  });
});

test('Android 0.13 raw WebSocket binary forwarding is byte-perfect in local fake upstream',async()=>{
  await withServer(async port=>{
    const a=await requestWs(port,headers());assert.match(a.status,/101/);
    let p=nextFrame(a.socket,a.left);a.socket.write(maskedFrame({op:'connect',host:'example.com',port:443}));
    let x=await p;assert.equal(x.value.op,'connected');
    const data=Buffer.from([0,1,2,127,128,254,255,10,13,0]);
    p=nextFrame(a.socket);
    a.socket.write(maskedFrame(data,2));
    x=await p;assert.equal(x.opcode,2);assert.ok(Buffer.isBuffer(x.value));assert.deepEqual(x.value,data);
    a.socket.destroy();
  });
});

test('Android 0.13 unconfigured service and unmasked binary fail safely',async()=>{
  await withServer(async port=>{
    const a=await requestWs(port,headers());assert.match(a.status,/503/);a.socket.destroy();
  },{noConfig:true});
  await withServer(async port=>{
    const a=await requestWs(port,headers());assert.match(a.status,/101/);
    let p=nextFrame(a.socket,a.left);
    a.socket.write(maskedFrame(Buffer.from('hello'),2));
    const x=await p;assert.equal(x.value.error,'not_connected');a.socket.destroy();
  });
});
