import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {makeServer} from '../server.mjs';
import {readConfig} from '../auth.mjs';
import {runRemoteWssHttpsProbe} from '../tools/wss-remote-probe.mjs';

async function listen(server){await new Promise(ok=>server.listen(0,'127.0.0.1',ok));return server.address().port;}
test('authenticated real WebSocket/TCP bytes pass through the Android-compatible lab path',async()=>{
  const fakeSockets=new Set(),gatewaySockets=new Set();
  const fake=net.createServer(c=>{fakeSockets.add(c);c.on('close',()=>fakeSockets.delete(c));c.pipe(c);});const port=await listen(fake);
  const env={IB_MASTER_KEY:'a'.repeat(64),IB_DEVICE_ID:'ib-test-device',IB_ANDROID013_COMPAT:'1',IB_SESSION_BYTE_CAP:'65536'};
  const gateway=makeServer(env,{android013Lookup:async()=>[{family:4,address:'93.184.216.34'}],android013Connect:()=>net.connect({host:'127.0.0.1',port})});
  gateway.on('connection',s=>{gatewaySockets.add(s);s.on('close',()=>gatewaySockets.delete(s));});
  const gp=await listen(gateway);
  try{
    const result=await runRemoteWssHttpsProbe({url:`ws://127.0.0.1:${gp}/tunnel`,config:readConfig(env),mode:'binary',timeout:15000});
    assert.equal(result.ok,true);assert.equal(result.mode,'ws_tcp_binary_echo');assert.ok(result.bytesReceived>10);
    gateway.recordProbeResult(result);
    const response=await fetch(`http://127.0.0.1:${gp}/selftestz`);const json=await response.json();
    assert.equal(json.state,'success');assert.equal(json.physicalAndroidVerified,false);assert.equal(json.operatorGbStored,false);
  }finally{
    for(const s of gatewaySockets)s.destroy();for(const s of fakeSockets)s.destroy();
    gateway.closeAllConnections?.();fake.closeAllConnections?.();
    await Promise.all([new Promise(ok=>gateway.close(ok)),new Promise(ok=>fake.close(ok))]);
  }
});
