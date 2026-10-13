import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
import {createPairing} from '../pairing.mjs';

async function createFixture(enabled=true){
  const config={key:Buffer.from('a'.repeat(64),'hex'),device:'ib-test-device'};
  const code='AbCdEfGhIjKlMnOpQrStUv';let logged='';
  const handler=createPairing(config,{enabled,code,emit:x=>logged=x});
  const server=createServer((req,res)=>{void Promise.resolve(handler(req,res));});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const url='http://127.0.0.1:'+server.address().port;
  return {server,url,code,config,logged};
}
test('Pairing is disabled unless opted in', async()=>{
  const f=await createFixture(false);try{const r=await fetch(f.url+'/pair');assert.equal(r.status,503);}finally{f.server.close();}
});
test('Rejects invalid code and wrong origin, gives device-scoped key once',async()=>{
  const f=await createFixture();try{
    assert.ok(f.logged.includes(f.code));
    const page=await fetch(f.url+'/pair');assert.equal(page.status,200);
    const path=f.url+'/v1/pair/redeem';
    const bad=await fetch(path,{method:'POST',body:JSON.stringify({code:'A'.repeat(22)}),headers:{'Content-Type':'application/json'}});
    assert.equal(bad.status,401);
    const origin=await fetch(path,{method:'POST',body:JSON.stringify({code:f.code}),headers:{Origin:'https://attacker.com'}});
    assert.equal(origin.status,403);
    const valid=await fetch(path,{method:'POST',body:JSON.stringify({code:f.code}),headers:{'Content-Type':'application/json'}});
    assert.equal(valid.status,200);
    const out=await valid.json();assert.equal(out.deviceId,f.config.device);
    assert.equal(out.deviceKey,createHmac('sha256',f.config.key).update('IB09-device:'+f.config.device).digest('hex'));
    assert.equal(out.wssUrl,'wss://internetbattery-gateway.onrender.com/tunnel');
    const again=await fetch(path,{method:'POST',body:JSON.stringify({code:f.code})});assert.equal(again.status,410);
    const after=await fetch(f.url+'/pair');assert.equal(after.status,410);
  }finally{f.server.close();}
});
