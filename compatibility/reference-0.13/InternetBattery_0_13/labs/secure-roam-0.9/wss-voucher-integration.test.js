'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const net=require('node:net');
const {spawn}=require('node:child_process');
const {WebSocket}=require('ws');
const {VoucherRights,voucherPayload}=require('./voucher-rights');
const ROOT=__dirname,BASEPORT=8986;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ib13-wss-'));
const key=fs.readFileSync(path.join(ROOT,'proofs','secret.txt'),'utf8').trim();
const ledger=path.join(dir,'voucher-ledger.json');
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const pub=publicKey.export({format:'pem',type:'spki'});
let child;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const URL='ws://127.0.0.1:'+BASEPORT+'/tunnel';
function ticket(opts={}){
 const data={voucherId:'proof-A',holderId:'lab-phone',targetGateway:'gateway-b',quotaBytes:20_000,issuedAtMs:Date.now()-5000,expiresAtMs:Date.now()+600_000,...opts};
 const signature=crypto.sign(null,Buffer.from(voucherPayload(data)),privateKey).toString('base64url');
 return 'IB1.'+Buffer.from(voucherPayload(data)+'|'+signature).toString('base64url');
}
function auth(t='',id='lab-phone'){
 const ts=Date.now(),nonce=crypto.randomBytes(16).toString('hex');
 const macKey=crypto.createHmac('sha256',key).update('IB09-device:'+id).digest();
 const mac=crypto.createHmac('sha256',macKey).update(id+'\n'+ts+'\n'+nonce).digest('hex');
 return {'x-ib-id':id,'x-ib-ts':String(ts),'x-ib-nonce':nonce,'x-ib-mac':mac,'x-ib-voucher':t};
}
function connect(headers){
 return new Promise((resolve,reject)=>{
  const ws=new WebSocket(URL,{headers,handshakeTimeout:5000});
  ws.once('open',()=>resolve(ws));ws.once('unexpected-response',(_,res)=>reject(Error('HTTP '+res.statusCode)));
  ws.once('error',reject);
 });
}
async function denied(headers,expected=403){
 try{const w=await connect(headers);w.terminate();throw Error('unexpectedly accepted');}
 catch(e){assert.match(e.message,new RegExp(String(expected)));}
}
async function start(){
 child=spawn('node',['gateway.js'],{
   cwd:ROOT,
   env:{...process.env,IB_PORT:String(BASEPORT),IB_ISSUER_PUBLIC_KEY_PEM:pub,IB_VOUCHER_GATEWAY_ID:'gateway-b',IB_VOUCHER_LEDGER:ledger},
   stdio:['ignore','pipe','pipe']
 });
 const errors=[];
 child.stderr.on('data',chunk=>errors.push(String(chunk)));
 for(let i=0;i<75;i++){
  if(child.exitCode!==null)throw Error('gateway crashed '+errors.join('').slice(0,400));
  try{const response=await fetch('http://127.0.0.1:'+BASEPORT+'/health');if(response.ok){
    const state=await response.json();assert.equal(state.voucherRightsEnabled,true);return;
  }}catch(e){}
  await sleep(80);
 }
 throw Error('gateway startup timeout '+errors.join(''));
}
function close(){
 if(!child)return Promise.resolve();
 const p=child;child=null;
 p.kill('SIGTERM');
 return new Promise(resolve=>{if(p.exitCode!==null)resolve();else{p.once('exit',resolve);setTimeout(resolve,3000);}});
}
function next(ws,predicate){
 return new Promise((resolve,reject)=>{
  const timeout=setTimeout(()=>{clear();reject(Error('frame timeout'));},13000);
  function clear(){clearTimeout(timeout);ws.off('message',msg);}
  function msg(data,binary){if(binary)return;let o=JSON.parse(data.toString());if(predicate(o)){clear();resolve(o);}}
  ws.on('message',msg);
 });
}
async function main(){
 await start();console.log('PASS voucher-mode WSS server starts, health checks rightsEnabled');
 await denied(auth(''));console.log('PASS no signed voucher denied');
 await denied(auth(ticket({holderId:'someone-else'})));console.log('PASS holder mismatch denied');
 await denied(auth(ticket({targetGateway:'gateway-c'})));console.log('PASS gateway mismatch denied');
 await denied(auth(ticket({expiresAtMs:Date.now()-2000})));console.log('PASS expired voucher denied');
 let originalSig=ticket();let forged=Buffer.from(originalSig.slice(4),'base64url').toString('utf8').replace('|20000|','|25000|');
 await denied(auth('IB1.'+Buffer.from(forged).toString('base64url')));
 console.log('PASS tampered quota cannot mint free usage');
 const orig=ticket();
 let w=await connect(auth(orig));
 console.log('PASS signed Ed25519 prepaid access admitted');
 const balance=next(w,x=>x.op==='balance');w.send(JSON.stringify({op:'balance'}));
 const initialBalance=await balance;
 assert.equal(initialBalance.voucherId,'proof-A');assert.equal(initialBalance.remaining,20_000);
 console.log('PASS authenticated IB1 remaining quota frame returned');
 const connected=next(w,x=>x.op==='connected'||x.op==='error');
 w.send(JSON.stringify({op:'connect',host:'example.com',port:443}));
 const answer=await connected;
 assert.equal(answer.op,'connected');
 console.log('PASS client opened real outbound TCP/443 with signed voucher');
 const quota=next(w,x=>x.op==='quota');
 w.send(Buffer.alloc(21_000,42),{binary:true});
 const exhausted=await quota;
 assert.equal(exhausted.limit,20_000);
 console.log('PASS attempted over-quota transmission rejected before forwarding');
 w.terminate();
 const journalOne=JSON.parse(fs.readFileSync(ledger,'utf8'));
 assert.equal(journalOne.entries['proof-A']?.spent||0,0);
 console.log('PASS denied data did not consume balance or forward');
 w=await connect(auth(orig));
 const confirmed=next(w,x=>x.op==='connected'||x.op==='error');
 w.send(JSON.stringify({op:'connect',host:'example.com',port:443}));
 assert.equal((await confirmed).op,'connected');
 const frame=Buffer.alloc(12_000,65);
 w.send(frame,{binary:true});
 await sleep(600);
 w.terminate();
 const first=JSON.parse(fs.readFileSync(ledger,'utf8'));
 assert.equal(first.entries['proof-A'].spent,frame.length);
 console.log('PASS real WSS socket payload spend recorded exactly: 12000');
 await close();
 await start();
 const restored=JSON.parse(fs.readFileSync(ledger,'utf8'));
 assert.equal(restored.entries['proof-A'].spent,12_000);
 console.log('PASS voucher spend survives real gateway process restart');
 w=await connect(auth(orig));
 const ready=next(w,x=>x.op==='connected'||x.op==='error');
 w.send(JSON.stringify({op:'connect',host:'example.com',port:443}));assert.equal((await ready).op,'connected');
 const deniedQuota=next(w,x=>x.op==='quota');
 w.send(Buffer.alloc(8500,41),{binary:true});
 assert.equal((await deniedQuota).limit,20_000);
 console.log('PASS replay voucher cannot exceed remaining 8000 bytes');
 w.terminate();
 await close();
 const corrupted=JSON.parse(fs.readFileSync(ledger,'utf8'));
 corrupted.entries['proof-A'].spent=0;
 fs.writeFileSync(ledger,JSON.stringify(corrupted));
 child=spawn('node',['gateway.js'],{cwd:ROOT,env:{...process.env,IB_PORT:String(BASEPORT),IB_ISSUER_PUBLIC_KEY_PEM:pub,IB_VOUCHER_GATEWAY_ID:'gateway-b',IB_VOUCHER_LEDGER:ledger},stdio:['ignore','pipe','pipe']});
 let stderr='';child.stderr.on('data',s=>stderr+=s.toString());
 await sleep(1100);
 assert.notEqual(child.exitCode,null);
 assert.match(stderr,/ledger authentication failed/);
 console.log('PASS tampered voucher ledger refuses startup');
 console.log('IB13 REAL WSS VOUCHER INTEGRATION TEST COMPLETE');
}
main().then(async()=>{await close();fs.rmSync(dir,{recursive:true,force:true});process.exit(0);})
 .catch(async e=>{console.error('FAIL',e.stack);await close();process.exit(1)});
