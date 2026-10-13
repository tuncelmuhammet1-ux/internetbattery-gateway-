import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import net from 'node:net';
import {once} from 'node:events';
import {makeServer} from '../server.mjs';
import {readConfig,signature} from '../auth.mjs';

const env={IB_MASTER_KEY:'b'.repeat(64), IB_DEVICE_ID:'phone-lab', IB_SESSION_BYTE_CAP:'20000'};
const config=readConfig(env);
const withServer = async (environment, body)=>{
  const server=makeServer(environment);
  const sockets=new Set();server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise((ok,fail)=>server.listen(0,'127.0.0.1',e=>e?fail(e):ok()));
  try{await body(server.address().port);}finally{for(const s of sockets)s.destroy();await new Promise(ok=>server.close(ok));}
};

function authHeaders(ts,nonce){return {'X-IB-Device':config.device,'X-IB-Timestamp':ts,'X-IB-Nonce':nonce,'X-IB-Signature':signature(config,ts,nonce)};}
function requestWs(port,headers){return new Promise((resolve,reject)=>{
  const sock=net.connect(port,'127.0.0.1');let buf=Buffer.alloc(0);
  const timeout=setTimeout(()=>{sock.destroy();reject(new Error('WS handshake timeout'));},4000);
  sock.once('error',e=>{clearTimeout(timeout);reject(e);});
  sock.on('data',data=>{
    buf=Buffer.concat([buf,data]);const end=buf.indexOf('\r\n\r\n');
    if(end<0)return;
    clearTimeout(timeout);sock.removeAllListeners('data');
    resolve({socket:sock,status:buf.toString('latin1',0,end).split('\r\n')[0],remaining:buf.subarray(end+4)});
  });
  sock.once('connect',()=>{
    const lines=['GET /ws HTTP/1.1','Host: 127.0.0.1:'+port,'Upgrade: websocket','Connection: Upgrade','Sec-WebSocket-Key: '+randomBytes(16).toString('base64'),'Sec-WebSocket-Version: 13',...Object.entries(headers).map(([k,v])=>k+': '+v),'',''];
    sock.write(lines.join('\r\n'));
  });
});}
function frameText(obj){const data=Buffer.from(JSON.stringify(obj)),mask=randomBytes(4);let pre;if(data.length<126){pre=Buffer.from([0x81,0x80|data.length]);}else{pre=Buffer.alloc(4);pre[0]=0x81;pre[1]=0xfe;pre.writeUInt16BE(data.length,2);}const m=Buffer.from(data);for(let i=0;i<m.length;i++)m[i]^=mask[i%4];return Buffer.concat([pre,mask,m]);}
function parseServerFrame(buf){if(buf.length<2)return null;let n=buf[1]&0x7f,off=2;if(n===126){if(buf.length<4)return null;n=buf.readUInt16BE(2);off=4;}else if(n===127){if(buf.length<10)return null;n=Number(buf.readBigUInt64BE(2));off=10;}if(buf.length<off+n)return null;return {object:JSON.parse(buf.subarray(off,off+n).toString()),consumed:off+n};}
function readFrame(socket,initial=Buffer.alloc(0)){return new Promise((resolve,reject)=>{
  let b=Buffer.from(initial);const timer=setTimeout(()=>{cleanup();reject(new Error('frame timeout'));},5000);
  function cleanup(){clearTimeout(timer);socket.off('data',feed);}
  function feed(chunk){b=Buffer.concat([b,chunk]);const frame=parseServerFrame(b);if(frame){cleanup();resolve(frame.object);}}
  socket.on('data',feed);feed(Buffer.alloc(0));
});}

test('healthz responds; readiness fails closed without configured auth',async()=>{
  await withServer({},async port=>{
    const health=await fetch('http://127.0.0.1:'+port+'/healthz');assert.equal(health.status,200);assert.equal((await health.json()).status,'alive');
    const ready=await fetch('http://127.0.0.1:'+port+'/readyz');assert.equal(ready.status,503);
    const notfound=await fetch('http://127.0.0.1:'+port+'/');assert.equal(notfound.status,404);
    const invalid=await requestWs(port,{});assert.match(invalid.status,/503/);invalid.socket.destroy();
  });
});

test('signed WebSocket upgrade, greeting and status; nonce reuse rejected',async()=>{
  await withServer(env,async port=>{
    const nonce=randomBytes(16).toString('hex'),ts=String(Date.now()),headers=authHeaders(ts,nonce);
    const a=await requestWs(port,headers);assert.match(a.status,/101/);
    const hello=await readFrame(a.socket,a.remaining);assert.equal(hello.t,'hello');assert.equal(hello.mode,'lab_ws1');
    const reply=readFrame(a.socket);a.socket.write(frameText({t:'status'}));assert.deepEqual(await reply,{t:'status',used:0,limit:20000,remaining:20000});
    const b=await requestWs(port,headers);assert.match(b.status,/401/);b.socket.destroy();
    a.socket.destroy();
  });
});

test('unauthorized websocket upgrade denied',async()=>{
  await withServer(env,async port=>{
    const wrong=await requestWs(port,{'X-IB-Device':'phone-lab','X-IB-Timestamp':String(Date.now()),'X-IB-Nonce':randomBytes(16).toString('hex'),'X-IB-Signature':'0'.repeat(64)});
    assert.match(wrong.status,/401/);wrong.socket.destroy();
  });
});

test('authenticated session rejects private host and unauthorized port without dialing',async()=>{
  await withServer(env,async port=>{
    const nonce=randomBytes(16).toString('hex'),ts=String(Date.now());
    const ws=await requestWs(port,authHeaders(ts,nonce));
    await readFrame(ws.socket,ws.remaining);
    let next=readFrame(ws.socket);
    ws.socket.write(frameText({t:'open',id:'a',host:'127.0.0.1',port:443}));
    assert.deepEqual(await next,{t:'error',id:'a',error:'destination_blocked'});
    next=readFrame(ws.socket);
    ws.socket.write(frameText({t:'open',id:'b',host:'example.com',port:22}));
    assert.deepEqual(await next,{t:'error',id:'b',error:'destination_blocked'});
    ws.socket.destroy();
  });
});
