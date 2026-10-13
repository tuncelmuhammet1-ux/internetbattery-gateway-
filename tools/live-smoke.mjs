import assert from 'node:assert/strict';
import {request as httpsRequest} from 'node:https';
import {randomBytes} from 'node:crypto';

const base = 'https://internetbattery-gateway.onrender.com';
const reports = [];
async function getJson(path,attempts=3) {
  let error;
  for(let i=0;i<attempts;i++){
    try {
      const res=await fetch(base+path,{redirect:'error',signal:AbortSignal.timeout(85000)});
      const obj=await res.json();
      return {status:res.status,json:obj};
    }catch(e){error=e;if(i+1<attempts)await new Promise(r=>setTimeout(r,3000));}
  }
  throw new Error(path+': '+String(error?.message||error));
}
function unauthUpgrade(){
 return new Promise((resolve,reject)=>{
   const req=httpsRequest(base+'/tunnel',{method:'GET',headers:{
      'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Version':'13',
      'Sec-WebSocket-Key':randomBytes(16).toString('base64')
    }},res=>{res.resume();resolve(res.statusCode)});
   req.setTimeout(90000,()=>req.destroy(new Error('timeout')));
   req.on('upgrade',(_,socket)=>{socket.destroy();reject(Error('unauthorized upgrade permitted'))});
   req.on('error',reject);req.end();
 });
}
async function run(){
 const h=await getJson('/healthz');
 assert.equal(h.status,200,'healthz should be 200');
 assert.equal(h.json.status,'alive');
 reports.push({check:'health',result:'ok',version:h.json.version});
 const r=await getJson('/readyz');
 assert.equal(r.status,200);
 assert.equal(r.json.ready,true);
 assert.equal(r.json.android013LabCompatibility,true);
 reports.push({check:'readiness',result:'ok',creditLedgerReady:!!r.json.creditLedgerReady,walletPortalReady:!!r.json.walletPortalReady,android013:r.json.android013LabCompatibility});
 const unauth=await unauthUpgrade();
 assert.equal(unauth,401,'Unpaired WebSocket must fail-closed with HTTP 401');
 reports.push({check:'negative WSS auth',result:'ok',http:unauth});
 const wallet=await fetch(base+'/v1/wallet/balance',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(85000)});
 assert.ok([401,503].includes(wallet.status),'unsigned balance must be blocked');
 reports.push({check:'unsigned wallet blocked',result:'ok',http:wallet.status});
 const info='\\n## INTERNET BATTERY remote gateway smoke checks\\n'+reports.map(v=>'- '+JSON.stringify(v)).join('\\n')+'\\n';
 console.log(info);
 if(process.env.GITHUB_STEP_SUMMARY){
  const fs=await import('node:fs/promises');
  await fs.appendFile(process.env.GITHUB_STEP_SUMMARY,info);
 }
}
run().catch(e=>{console.error('LIVE_GATEWAY_SMOKE_FAILED',String(e?.message||e));process.exitCode=1;});
