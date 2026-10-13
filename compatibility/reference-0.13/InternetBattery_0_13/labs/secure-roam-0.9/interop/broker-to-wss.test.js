'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const crypto=require('node:crypto'),tls=require('node:tls'),{Duplex}=require('node:stream'),{spawn}=require('node:child_process');
const {WebSocket}=require('ws');
const source=fs.readFileSync('/tmp/ib13-cross-language-token.txt','utf8');
const lines=Object.fromEntries(source.trim().split('\n').map(x=>x.split(/=(.*)/s).slice(0,2)));
const key=crypto.createPublicKey({key:Buffer.from(lines.PUBLIC_DER_B64,'base64'),format:'der',type:'spki'});
const pem=key.export({format:'pem',type:'spki'}),voucher=lines.IB1;
const root=path.dirname(__dirname),port=8987;
const journal='/tmp/ib13-cross-language-voucher-ledger.json';
try{fs.unlinkSync(journal)}catch(e){if(e.code!=='ENOENT')throw e;}
const master=fs.readFileSync(path.join(root,'proofs','secret.txt'),'utf8').trim();
let server=null;const wait=ms=>new Promise(r=>setTimeout(r,ms));
function headers(){
 const id='provider-1',ts=Date.now(),nonce=crypto.randomBytes(16).toString('hex');
 const derived=crypto.createHmac('sha256',master).update('IB09-device:'+id).digest();
 const mac=crypto.createHmac('sha256',derived).update(id+'\n'+ts+'\n'+nonce).digest('hex');
 return {'x-ib-id':id,'x-ib-ts':String(ts),'x-ib-nonce':nonce,'x-ib-mac':mac,'x-ib-voucher':voucher};
}
function incoming(ws,predicate){
 return new Promise((resolve,reject)=>{
  const t=setTimeout(()=>{ws.off('message',onMsg);reject(Error('timeout'))},12000);
  function onMsg(data,binary){if(binary)return;const m=JSON.parse(data);if(predicate(m)){ws.off('message',onMsg);clearTimeout(t);resolve(m)}}
  ws.on('message',onMsg);
 });
}
async function run(){
 server=spawn('node',['gateway.js'],{cwd:root,env:{...process.env,IB_PORT:String(port),IB_ISSUER_PUBLIC_KEY_PEM:pem,IB_VOUCHER_GATEWAY_ID:'gateway-b',IB_VOUCHER_LEDGER:journal}});
 for(let i=0;i<75;i++){try{const r=await fetch('http://127.0.0.1:'+port+'/health');if(r.ok)break;}catch(e){}await wait(100)}
 const ws=await new Promise((resolve,reject)=>{
  const socket=new WebSocket('ws://127.0.0.1:'+port+'/tunnel',{headers:headers()});
  socket.once('open',()=>resolve(socket));socket.once('error',reject);socket.once('unexpected-response',(_,r)=>reject(Error('HTTP '+r.statusCode)));
 });
 const b=incoming(ws,m=>m.op==='balance');
 ws.send(JSON.stringify({op:'balance'}));
 const balance=await b;
 assert.equal(balance.voucherId,'cross-lang-v13');
 assert.equal(balance.remaining,20000);
 console.log('PASS Kotlin ledger issued IB1; Node WSS gateway verified signature and 20,000 byte unused balance');
 const connected=incoming(ws,m=>m.op==='connected'||m.op==='error');
 ws.send(JSON.stringify({op:'connect',host:'example.com',port:443}));
 const c=await connected;assert.equal(c.op,'connected');
 console.log('PASS Kotlin-issued voucher authorized a real outbound TCP/443 socket');
 const channel=new Duplex({
  read() {},
  write(chunk,_enc,done){ws.send(chunk,{binary:true},done);}
 });
 ws.on('message',(data,binary)=>{if(binary)channel.push(data);else {const msg=JSON.parse(data);if(msg.op==='end')channel.push(null);}});
 ws.on('close',()=>channel.push(null));
 const secure=tls.connect({socket:channel,servername:'example.com',rejectUnauthorized:true});
 await Promise.race([new Promise((resolve,reject)=>{secure.once('secureConnect',resolve);secure.once('error',reject);}),wait(15000).then(()=>{throw Error('TLS timeout')})]);
 console.log('PASS cross-language voucher authorized verified TLS handshake');
 const parts=[];secure.on('data',b=>parts.push(b));
 secure.end('GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n');
 await Promise.race([new Promise((resolve,reject)=>{secure.once('end',resolve);secure.once('error',reject);}),wait(12000).then(()=>{throw Error('HTTP timeout')})]);
 const body=Buffer.concat(parts).toString();
 assert.match(body,/HTTP\/1\.1 (200|301)/);
 console.log('PASS signed credit was actually spent on public HTTPS response');
 ws.close();
 await wait(150);
 const ledger=JSON.parse(fs.readFileSync(journal,'utf8'));
 assert.ok(ledger.entries['cross-lang-v13'].spent>0);
 assert.ok(ledger.entries['cross-lang-v13'].spent<=20000);
 console.log('PASS gateway measured and debited bytes = '+ledger.entries['cross-lang-v13'].spent);
 console.log('IB13 CROSS LANGUAGE CONTRIBUTION → CREDIT → REMOTE HTTPS SPEND PASS');
}
run().then(()=>{server?.kill('SIGTERM');process.exit(0);}).catch(e=>{console.error('FAIL',e.message);server?.kill('SIGTERM');process.exit(1);});
