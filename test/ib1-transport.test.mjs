import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac, generateKeyPairSync, randomBytes} from 'node:crypto';
import net from 'node:net';
import {PassThrough} from 'node:stream';
import {makeServer} from '../server.mjs';
import {readConfig} from '../auth.mjs';
import {android013Signature} from '../android013.mjs';
import {makeIB1,GB} from '../voucher.mjs';

const id='ib-device-13';
const pair=generateKeyPairSync('ed25519');
const priv=pair.privateKey.export({format:'pem',type:'pkcs8'}),pub=pair.publicKey.export({format:'pem',type:'spki'});
const env={IB_MASTER_KEY:'3f'.repeat(32),IB_DEVICE_ID:id,IB_SESSION_BYTE_CAP:'7000',IB_ANDROID013_COMPAT:'1',
  IB_CREDIT_DB_ENABLED:'1',IB_WALLET_HTTP_ENABLED:'1',IB_ISSUER_PRIVATE_KEY_PEM:priv,IB_ISSUER_PUBLIC_KEY_PEM:pub,IB_VOUCHER_GATEWAY_ID:'ib-gw1'};
const cfg=readConfig(env);
const ledger={
  spent:0, directions:[], available:1*GB,
  async balance(v){return {voucherId:v.voucherId,quotaBytes:v.quotaBytes,spent:this.spent,remaining:Math.min(v.quotaBytes-this.spent,this.available)};},
  async spend(v,bytes,{direction}){
    if(this.spent+bytes>v.quotaBytes)return {accepted:false,spent:this.spent,remaining:0};
    this.spent+=bytes;this.available-=bytes;this.directions.push(direction);
    return {accepted:true,spent:this.spent,remaining:Math.min(v.quotaBytes-this.spent,this.available)};
  },
  async wallet(){return {holderId:id,creditedBytes:GB,spentBytes:this.spent,availableBytes:this.available};},
  async claimNonce(){return true;}
};
function voucher(){const n=Date.now();return makeIB1({voucherId:'v-'+randomBytes(8).toString('hex'),holderId:id,gatewayId:'ib-gw1',quotaBytes:GB,issuedAtMs:n,expiresAtMs:n+3_600_000},priv);}
const headers=()=>{const ts=String(Date.now()),nonce=randomBytes(16).toString('hex');return {'X-IB-ID':id,'X-IB-TS':ts,'X-IB-Nonce':nonce,'X-IB-MAC':android013Signature(cfg,id,ts,nonce)};};
const fakeLookup=async()=>[{address:'93.184.216.34',family:4}];
const fakeConnect=()=>{const s=new PassThrough();process.nextTick(()=>s.emit('connect'));return s;};
async function serverWith(fn,opts={}){
  const s=makeServer(env,{ledger:opts.ledger||ledger,android013Lookup:fakeLookup,android013Connect:fakeConnect});
  const sockets=new Set();s.on('connection',x=>{sockets.add(x);x.on('close',()=>sockets.delete(x));});
  await new Promise(ok=>s.listen(0,'127.0.0.1',ok));
  try{await fn(s.address().port);}finally{for(const x of sockets)x.destroy();await new Promise(ok=>s.close(ok));}
}
function masked(data,opcode=1){
 const body=Buffer.isBuffer(data)?data:Buffer.from(JSON.stringify(data));const key=randomBytes(4),n=body.length;
 const head=n<126?Buffer.from([128|opcode,128|n]):Buffer.from([128|opcode,0xfe,(n>>8)&255,n&255]);
 const bytes=Buffer.from(body);for(let i=0;i<n;i++)bytes[i]^=key[i&3];return Buffer.concat([head,key,bytes]);
}
async function connect(port,token){
 return new Promise((resolve,reject)=>{
  const s=net.connect(port,'127.0.0.1');let buf=Buffer.alloc(0);
  const timer=setTimeout(()=>{s.destroy();reject(Error('handshake timeout'));},4000);
  s.once('error',e=>{clearTimeout(timer);reject(e);});
  s.on('data',chunk=>{buf=Buffer.concat([buf,chunk]);const pos=buf.indexOf('\r\n\r\n');if(pos<0)return;
    s.removeAllListeners('data');clearTimeout(timer);
    resolve({socket:s,status:buf.toString('latin1',0,pos).split('\r\n')[0],initial:buf.subarray(pos+4)});
  });
  s.once('connect',()=>s.write(['GET /tunnel HTTP/1.1',`Host: 127.0.0.1:${port}`,'Upgrade: websocket','Connection: Upgrade',
    'Sec-WebSocket-Key: '+randomBytes(16).toString('base64'),'Sec-WebSocket-Version: 13',
    ...Object.entries({...headers(),...(token?{'X-IB-Voucher':token}:{})}).map(([a,b])=>a+': '+b),'',''].join('\r\n')));
 });
}
function parse(b){if(b.length<2)return null;let len=b[1]&127,off=2;if(len===126){if(b.length<4)return null;len=b.readUInt16BE(2);off=4;}if(len===127){if(b.length<10)return null;len=Number(b.readBigUInt64BE(2));off=10;}if(b.length<off+len)return null;const kind=b[0]&15,payload=b.subarray(off,off+len);return {kind,value:kind===1?JSON.parse(payload.toString()):payload,left:b.subarray(off+len)};}
function next(s,initial=Buffer.alloc(0)){
 return new Promise((resolve,reject)=>{let buf=Buffer.from(initial);const timer=setTimeout(()=>{cleanup();reject(Error('frame timeout'));},4000);
   function cleanup(){clearTimeout(timer);s.off('data',feed);}function feed(c){buf=Buffer.concat([buf,c]);const p=parse(buf);if(p){cleanup();resolve(p);}}
   s.on('data',feed);feed(Buffer.alloc(0));
 });
}

test('Android IB1 voucher preflight, bidirectional TCP echo and reconnected balance',async()=>{
 ledger.spent=0;ledger.available=GB;ledger.directions=[];
 await serverWith(async port=>{
   const token=voucher();const a=await connect(port,token);assert.match(a.status,/101/);
   let read=next(a.socket,a.initial);a.socket.write(masked({op:'balance'}));let r=await read;
   assert.equal(r.value.op,'balance');assert.equal(r.value.remaining,GB);
   read=next(a.socket);a.socket.write(masked({op:'connect',host:'example.com',port:443}));r=await read;assert.equal(r.value.op,'connected');
   const data=Buffer.from([0,1,2,3,240,255,10]);
   read=next(a.socket);a.socket.write(masked(data,2));r=await read;assert.equal(r.kind,2);assert.deepEqual(r.value,data);
   assert.equal(ledger.spent,data.length*2);assert.deepEqual(ledger.directions,['uplink','downlink']);
   a.socket.destroy();
   const b=await connect(port,token);assert.match(b.status,/101/);
   read=next(b.socket,b.initial);b.socket.write(masked({op:'balance'}));r=await read;
   assert.equal(r.value.spent,data.length*2);assert.equal(r.value.remaining,GB-2*data.length);
   b.socket.destroy();
 });
});

test('forged IB1 voucher and unavailable credit ledger are rejected before upgrade',async()=>{
 await serverWith(async port=>{
   let c=await connect(port,'IB1.badfake');assert.match(c.status,/403/);c.socket.destroy();
 });
 await serverWith(async port=>{
   let c=await connect(port,voucher());assert.match(c.status,/503/);c.socket.destroy();
 },{ledger:{balance:async()=>{throw Error('database_down');},spend:ledger.spend}});
});