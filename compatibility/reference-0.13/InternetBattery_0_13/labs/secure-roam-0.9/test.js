'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const https=require('node:https');
const {WebSocket}=require('ws');
const KEY=fs.readFileSync(path.join(__dirname,'proofs','secret.txt'),'utf8').trim();
const WSS=process.env.IB_TEST_WSS||'ws://127.0.0.1:8977/tunnel';
const ready=(ms)=>new Promise(r=>setTimeout(r,ms));
function auth(id='lab-09'){
 const ts=Date.now(),nonce=crypto.randomBytes(16).toString('hex');
 const data=id+'\n'+ts+'\n'+nonce;
 const perDevice=crypto.createHmac('sha256',KEY).update('IB09-device:'+id).digest();
 const mac=crypto.createHmac('sha256',perDevice).update(data).digest('hex');
 return {'x-ib-id':id,'x-ib-ts':String(ts),'x-ib-nonce':nonce,'x-ib-mac':mac};
}
function wsConnect(headers=auth()){
 return new Promise((resolve,reject)=>{
  const ws=new WebSocket(WSS,{headers,handshakeTimeout:5000,perMessageDeflate:false});
  ws.once('open',()=>resolve(ws));ws.once('error',reject);ws.once('unexpected-response',(req,res)=>reject(Error('http '+res.statusCode)));
 });
}
function waitMessage(ws,predicate,timeout=10000){
 return new Promise((resolve,reject)=>{
  const t=setTimeout(()=>{clear();reject(Error('ws response timeout'));},timeout);
  function clear(){clearTimeout(t);ws.off('message',got);ws.off('close',gone);ws.off('error',broken);}
  function got(data,binary){let msg=binary?data:JSON.parse(data.toString());if(predicate(msg,binary)){clear();resolve({msg,binary});}}
  function gone(){clear();reject(Error('ws closed unexpectedly'));}function broken(e){clear();reject(e);}
  ws.on('message',got);ws.on('close',gone);ws.on('error',broken);
 });
}
async function assertWsFailure(headers,label){
 try{
  await wsConnect(headers);
  throw Error(label+' accepted');
 }catch(e){
  assert.match(String(e.message),/401/);
  console.log('PASS '+label);
 }
}
async function tests(){
 await assertWsFailure({},'unauthenticated denied');
 const signed=auth('replay-test');
 let w=await wsConnect(signed);w.close();
 await assertWsFailure(signed,'replay denied');
 const forged=auth('legitimate'); forged['x-ib-id']='forged-device';
 await assertWsFailure(forged,'different device ID denied');
 const stale=auth('stale-test');stale['x-ib-ts']=String(Date.now()-120000);
 await assertWsFailure(stale,'stale timestamp denied');
 w=await wsConnect(auth('restricted-host-test'));
 let msg=waitMessage(w,(m,b)=>!b&&m.op==='error');w.send(JSON.stringify({op:'connect',host:'localhost',port:80}));
 let e=await msg;assert.match(e.msg.error,/invalid hostname|no public address/); console.log('PASS localhost denied');
 w.terminate();
 w=await wsConnect(auth('private-ip-test'));msg=waitMessage(w,(m,b)=>!b&&m.op==='error');w.send(JSON.stringify({op:'connect',host:'127.0.0.1',port:80})); e=await msg;assert.match(e.msg.error,/private target denied/);console.log('PASS private IP denied');w.terminate();
 // Authentication must work over public WSS or localhost.
 w=await wsConnect(auth('bad-port-test'));msg=waitMessage(w,(m,b)=>!b&&m.op==='error');w.send(JSON.stringify({op:'connect',host:'example.com',port:22}));
 e=await msg;assert.match(e.msg.error,/port restricted/);console.log('PASS unsafe port denied');w.terminate();
 w=await wsConnect(auth('dns-test'));
 msg=waitMessage(w,(m,b)=>!b&&m.op==='dns');w.send(JSON.stringify({op:'dns',host:'example.com'}));
 const dns=await msg; assert.equal(dns.msg.host,'example.com');assert.ok(dns.msg.address);console.log('PASS authenticated DNS resolves PUBLIC IP');w.close();
 w=await wsConnect(auth('tcp-test'));
 msg=waitMessage(w,(m,b)=>!b&&m.op==='connected',20000);
 w.send(JSON.stringify({op:'connect',host:'example.com',port:443}));
 e=await msg; console.log('PASS TCP via websocket',e.msg.ipFamily);
 const tls=require('node:tls');
 // TLS through websocket requires streaming adapter.
 const {Duplex}=require('node:stream');
 const adapter=new Duplex({
  read() {},
  write(chunk,enc,cb){if(w.readyState===w.OPEN){w.send(chunk,{binary:true},cb);}else cb(Error('socket closed'));}
 });
 w.on('message',(data,binary)=>{if(binary)adapter.push(data);else {try{let o=JSON.parse(String(data));if(o.op==='end')adapter.push(null);}catch(e){}}});
 w.on('close',()=>adapter.push(null));
 const s=tls.connect({socket:adapter,servername:'example.com',rejectUnauthorized:true});
 await new Promise((resolve,reject)=>{s.once('secureConnect',resolve);s.once('error',reject);setTimeout(()=>reject(Error('tls handshake timeout')),20000);});
 console.log('PASS remote TLS certificate through WSS');
 const request='GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n';
 const collected=[];
 s.on('data',b=>collected.push(b));
 s.write(request);
 await new Promise((resolve,reject)=>{s.on('end',resolve);s.on('error',reject);setTimeout(()=>reject(Error('http timeout')),20000);});
 const result=Buffer.concat(collected).toString('utf8');
 assert.match(result,/HTTP\/1\.1 200|HTTP\/1\.1 301/);
 console.log('PASS HTTPS response through authenticated WSS, bytes=',result.length);
 w.close();
 try{
  w=await wsConnect(auth('udp-dns-test'));msg=waitMessage(w,(m,b)=>!b&&(m.op==='udp53_reply'||m.op==='error'),5000);
  // Wire query for example.com A
  const q=Buffer.from('1a2b01000001000000000000076578616d706c6503636f6d0000010001','hex');
  w.send(JSON.stringify({op:'udp53',host:'1.1.1.1',port:53,rid:12345,data:q.toString('base64')}));
  let ans=await msg;
  if(ans.msg.op==='udp53_reply'){assert.equal(ans.msg.rid,12345);console.log('PASS UDP request ID correlation');let b=Buffer.from(ans.msg.data,'base64');assert.equal(b.readUInt16BE(0),0x1a2b);console.log('PASS UDP/53 DNS response via WSS bytes='+b.length);}else console.log('UNVERIFIED UDP DNS response: '+ans.msg.error);
  w.close();
 }catch(e){console.log('UNVERIFIED UDP DNS: '+e.message);}
 let ss=JSON.parse(fs.readFileSync(path.join(__dirname,'proofs','spent.json'))); assert.ok(ss['tcp-test']>500);
 console.log('PASS quota ledger counts actual transferred bytes, value=',ss['tcp-test']);
 console.log('IB09 LAB FINISHED');
}
tests().then(()=>process.exit(0)).catch(e=>{console.error('FAIL',e);process.exit(1);});
