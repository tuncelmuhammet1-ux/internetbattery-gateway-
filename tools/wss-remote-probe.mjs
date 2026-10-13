/** Authenticated external WSS -> TCP -> TLS/HTTPS self-check. Never logs device keys.
 * Internal lab proof, not a physical phone or roaming test.
 */
import tls from 'node:tls';
import net from 'node:net';
import {Duplex} from 'node:stream';
import {createHash,randomBytes} from 'node:crypto';
import {android013Signature} from '../android013.mjs';

const GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function websocketFrame(op,data){
 const b=Buffer.from(data),mask=randomBytes(4);let h;
 if(b.length<126){h=Buffer.from([0x80|op,0x80|b.length]);}
 else if(b.length<65536){h=Buffer.alloc(4);h[0]=0x80|op;h[1]=0x80|126;h.writeUInt16BE(b.length,2);}
 else throw Error('selftest_frame_too_large');
 const p=Buffer.from(b);for(let i=0;i<p.length;i++)p[i]^=mask[i%4];return Buffer.concat([h,mask,p]);
}
export async function openAuthenticatedWs({url,config,timeout=25000}){
 if(!config||!config.key||!config.device)throw Error('missing_auth_config');
 const u=new URL(url);
 if(!['ws:','wss:'].includes(u.protocol)||u.pathname!=='/tunnel'||u.username||u.password||u.search||u.hash)throw Error('invalid_probe_url');
 const secure=u.protocol==='wss:';
 if(!secure&&!['127.0.0.1','localhost'].includes(u.hostname))throw Error('plaintext_probe_must_be_local');
 const hostname=u.hostname,port=Number(u.port||(secure?443:80));
 const socket=secure?tls.connect({host:hostname,port,servername:hostname,rejectUnauthorized:true,ALPNProtocols:['http/1.1']}):net.connect({host:hostname,port});
 const nonce=randomBytes(16).toString('hex'),ts=String(Date.now());
 const key=randomBytes(16).toString('base64');
 const accept=createHash('sha1').update(key+GUID).digest('base64');
 const mac=android013Signature(config,config.device,ts,nonce);
 const headers=[`GET /tunnel HTTP/1.1`,`Host: ${hostname}${u.port?':'+port:''}`,'Upgrade: websocket','Connection: Upgrade','Sec-WebSocket-Version: 13',`Sec-WebSocket-Key: ${key}`,`X-IB-ID: ${config.device}`,`X-IB-TS: ${ts}`,`X-IB-Nonce: ${nonce}`,`X-IB-MAC: ${mac}`,'',''].join('\r\n');
 let buffer=Buffer.alloc(0),ready=false,stopped=false,expectHttp=true;
 const notices=[],waiting=[];
 let binaryReceiver=()=>{};
 let failReady=()=>{},passReady=()=>{};
 const opening=new Promise((resolve,reject)=>{passReady=resolve;failReady=reject;});
 const timer=setTimeout(()=>stop(Error('selftest_timeout')),timeout);
 timer.unref?.();
 function pushText(x){
   for(let i=0;i<waiting.length;i++){if(waiting[i].predicate(x)){
     const w=waiting.splice(i,1)[0];clearTimeout(w.timer);w.resolve(x);return;
   }}notices.push(x);
 }
 function stop(err){if(stopped)return;stopped=true;clearTimeout(timer);socket.destroy();
   if(!ready)failReady(err||Error('gateway_closed_before_upgrade'));
   while(waiting.length){const w=waiting.pop();clearTimeout(w.timer);w.reject(err||Error('gateway_closed'));}
 }
 socket.once(secure?'secureConnect':'connect',()=>socket.write(headers));
 socket.on('error',e=>stop(Error('gateway_network_'+(e.code||'error'))));
 socket.on('close',()=>stop(Error('gateway_closed')));
 socket.on('data',data=>{
   if(stopped)return;
   buffer=Buffer.concat([buffer,data]);
   if(buffer.length>512*1024){stop(Error('selftest_buffer_cap'));return;}
   if(expectHttp){
     const e=buffer.indexOf('\r\n\r\n');if(e<0)return;
     const raw=buffer.subarray(0,e+4).toString('ascii');buffer=buffer.subarray(e+4);
     if(!/^HTTP\/1\.1 101\b/.test(raw)|| !new RegExp('^sec-websocket-accept: '+accept.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\r?$', 'im').test(raw)){
       stop(Error('gateway_upgrade_rejected_'+(raw.match(/^HTTP\/1\.1 (\d{3})/)?.[1]||'protocol')));return;
     }
     expectHttp=false;ready=true;passReady();
   }
   while(buffer.length>=2&&!stopped){
     const a=buffer[0],b=buffer[1];if(!(a&0x80)||(a&0x70)||(b&0x80)){stop(Error('invalid_server_ws_frame'));return;}
     let n=b&0x7f,h=2;
     if(n===126){if(buffer.length<4)break;n=buffer.readUInt16BE(2);h=4;}
     else if(n===127){if(buffer.length<10)break;const big=buffer.readBigUInt64BE(2);if(big>262144n){stop(Error('oversize_frame'));return;}n=Number(big);h=10;}
     if(n>262144){stop(Error('oversize_frame'));return;}
     if(buffer.length<h+n)break;
     const frame=buffer.subarray(h,h+n),op=a&0x0f;buffer=buffer.subarray(h+n);
     if(op===1){try{pushText(JSON.parse(frame.toString('utf8')));}catch{stop(Error('invalid_ws_json'));return;}}
     else if(op===2){binaryReceiver(frame);}
     else if(op===9){socket.write(websocketFrame(10,frame));}
     else if(op===8){stop(Error('server_ws_closed'));return;}
   }
 });
 await opening;
 return {
   sendJson(msg){if(stopped)throw Error('gateway_closed');socket.write(websocketFrame(1,Buffer.from(JSON.stringify(msg))));},
   sendBinary(b){if(stopped)throw Error('gateway_closed');socket.write(websocketFrame(2,b));},
   setBinaryReceiver(f){binaryReceiver=f;},
   async waitJson(predicate,ms=10000){
     const i=notices.findIndex(predicate);if(i!==-1)return notices.splice(i,1)[0];
     return new Promise((resolve,reject)=>{
       const ent={predicate,resolve,reject,timer:setTimeout(()=>{const idx=waiting.indexOf(ent);if(idx!==-1)waiting.splice(idx,1);reject(Error('ws_reply_timeout'));},ms)};
       waiting.push(ent);
     });
   },
   close(){stop();}
 };
}
export async function runRemoteWssHttpsProbe({url,config,remoteHost='example.com',timeout=30000,mode='https'}={}){
 const begin=Date.now(),ws=await openAuthenticatedWs({url,config,timeout});
 try{
   ws.sendJson({op:'dns',host:remoteHost});
   const dns=await ws.waitJson(x=>x?.op==='dns'||x?.op==='error',12000);
   if(dns.op!=='dns'||dns.host!==remoteHost||!dns.address)throw Error('remote_dns_failed');
   ws.sendJson({op:'connect',host:remoteHost,port:443});
   const open=await ws.waitJson(x=>x?.op==='connected'||x?.op==='error',12000);
   if(open.op!=='connected')throw Error('remote_tcp_connect_failed');
   if(mode==='binary'){
     const marker='IB-PROBE-'+randomBytes(8).toString('hex');
     const echoed=new Promise((resolve,reject)=>{const timeoutId=setTimeout(()=>reject(Error('echo_timeout')),5000);
       ws.setBinaryReceiver(payload=>{if(payload.toString()===marker){clearTimeout(timeoutId);resolve(payload.length);}});
     });
     ws.sendBinary(Buffer.from(marker));const length=await echoed;
     return {ok:true,mode:'ws_tcp_binary_echo',bytesReceived:length,durationMs:Date.now()-begin};
   }
   // Native TLS and certificate validation occur over the WSS TCP relay.
   const sock=new Duplex({read(){},write(b,_enc,callback){try{ws.sendBinary(b);callback();}catch(e){callback(e);}}});
   ws.setBinaryReceiver(data=>sock.push(data));
   const secure=tls.connect({socket:sock,servername:remoteHost,rejectUnauthorized:true,ALPNProtocols:['http/1.1']});
   let secureReady=false;
   const result=await new Promise((resolve,reject)=>{
     const timer=setTimeout(()=>reject(Error('https_timeout')),14000);
     let response=Buffer.alloc(0),done=false;
     const close=(e,v)=>{if(done)return;done=true;clearTimeout(timer);if(e)reject(e);else resolve(v);};
     secure.once('secureConnect',()=>{
       secureReady=true;
       if(!secure.authorized){close(Error('remote_tls_unauthorized'));return;}
       secure.write(`GET / HTTP/1.1\r\nHost: ${remoteHost}\r\nConnection: close\r\nUser-Agent: InternetBattery-Lab-Probe\r\n\r\n`);
     });
     secure.on('data',buf=>{
       response=Buffer.concat([response,buf]);if(response.length>100000)return close(Error('https_response_too_large'));
       const head=response.toString('ascii',0,Math.min(response.length,100));
       const status=head.match(/^HTTP\/1\.[01] (\d{3})/);
       if(status&&response.includes(Buffer.from('\r\n\r\n')))close(null,{httpStatus:Number(status[1]),bytes:response.length,tlsAuthorized:secure.authorized});
     });
     secure.once('error',e=>close(Error('upstream_tls_'+(e.code||e.message))));
     secure.once('end',()=>{if(!done)close(Error('https_closed_early'));});
   });
   if(!secureReady||result.httpStatus<200||result.httpStatus>=400)throw Error('remote_https_invalid_response');
   secure.destroy();
   return {ok:true,mode:'wss_tcp_tls_https',httpStatus:result.httpStatus,bytesReceived:result.bytes,durationMs:Date.now()-begin};
 }finally{ws.close();}
}
