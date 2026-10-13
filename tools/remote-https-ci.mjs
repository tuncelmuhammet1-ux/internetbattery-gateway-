// CI-only real public HTTPS path over the Android-compatible WSS protocol.
// Local WebSocket server -> public TCP -> real certificate-verified HTTPS.
import {makeServer} from '../server.mjs';
import {readConfig} from '../auth.mjs';
import {runRemoteWssHttpsProbe} from './wss-remote-probe.mjs';

const env={IB_MASTER_KEY:'d'.repeat(64),IB_DEVICE_ID:'ib-public-https-ci',IB_ANDROID013_COMPAT:'1',IB_SESSION_BYTE_CAP:'1048576'};
const server=makeServer(env),sockets=new Set();
server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
try{
 const url=`ws://127.0.0.1:${server.address().port}/tunnel`;
 const result=await runRemoteWssHttpsProbe({url,config:readConfig(env),timeout:25000});
 if(!result.ok||!result.tlsAuthorized||result.httpStatus<200||result.httpStatus>=400)throw Error('https_not_verified');
 console.log('IB_REMOTE_HTTPS_OVER_WSS_SUCCESS '+JSON.stringify(result));
}finally{
 for(const s of sockets)s.destroy();server.closeAllConnections?.();await new Promise(ok=>server.close(ok));
}
