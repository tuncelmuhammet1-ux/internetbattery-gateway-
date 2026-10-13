'use strict';
const http=require('node:http');
const net=require('node:net');
const dns=require('node:dns').promises;
const dgram=require('node:dgram');
const fs=require('node:fs');
const crypto=require('node:crypto');
const path=require('node:path');
const {WebSocketServer}=require('ws');
const {VoucherRights}=require('./voucher-rights');
const ROOT=__dirname, PORT=Number(process.env.IB_PORT||8977);
const KEY=fs.readFileSync(path.join(ROOT,'proofs','secret.txt'),'utf8').trim();
const LIMIT=5*1024*1024; // LAB quota measured in transmitted bytes, per authenticated device ID
const LEDGER=path.join(ROOT,'proofs','spent.json');
const ISSUER_PUB=process.env.IB_ISSUER_PUBLIC_KEY_PEM||'';
const RIGHTS_GATEWAY=process.env.IB_VOUCHER_GATEWAY_ID||'';
const rights=ISSUER_PUB ? new VoucherRights({
  issuerPublicKeyPem:ISSUER_PUB,
  gatewayId:RIGHTS_GATEWAY,
  ledgerPath:process.env.IB_VOUCHER_LEDGER||path.join(ROOT,'proofs','signed-voucher-ledger.json'),
  ledgerMacKey:crypto.createHmac('sha256',KEY).update('IB13-voucher-journal-v1').digest()
}) : null;
let spend={};
try{spend=JSON.parse(fs.readFileSync(LEDGER,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
const nonceSeen=new Map();
const clients=new Map();
function persist(){
 const tmp=LEDGER+'.tmp';
 fs.writeFileSync(tmp,JSON.stringify(spend),{mode:0o600});
 fs.renameSync(tmp,LEDGER);
}
function charge(id,count){
 if(!Number.isSafeInteger(count)||count<0)throw Error('invalid byte count');
 if((spend[id]||0)+count>LIMIT)return false;
 spend[id]=(spend[id]||0)+count;
 persist();
 return true;
}
function publicIp(ip){
 const version=net.isIP(ip);
 if(version===4){
  const p=ip.split('.').map(Number),a=p[0],b=p[1],c=p[2];
  if(a<1||a>=224)return false;
  if(a===10||a===127||a===0||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19)||a===192&&b===0||a===192&&b===88||a===192&&b===0&&c===2||a===198&&b===51&&c===100||a===203&&b===0&&c===113)return false;
  return true;
 }
 if(version===6){
  if(ip.includes('%'))return false;
  if(ip.startsWith('::ffff:'))return publicIp(ip.replace('::ffff:',''));
  const first=parseInt(ip.slice(0,4),16);
  return Number.isFinite(first)&&first>=0x2000&&first<0x4000;
 }
 return false;
}
const server=http.createServer((req,res)=>{
 res.setHeader('Cache-Control','no-store');
 if(req.url==='/health'&&req.method==='GET'){
  res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({ok:true,kind:'authenticated_wss_relay',lab:true,accounting:'real_bytes',voucherRightsEnabled:!!rights,android_verified:false,network_required:true}));return;
 }
 res.writeHead(404);res.end('not found');
});
const wss=new WebSocketServer({noServer:true,maxPayload:65536,perMessageDeflate:false});
function fail(socket,code,msg){socket.write('HTTP/1.1 '+code+' '+msg+'\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');socket.destroy();}
function check(req){
 const id=String(req.headers['x-ib-id']||'');
 const ts=Number(req.headers['x-ib-ts']||0);
 const nonce=String(req.headers['x-ib-nonce']||'');
 const mac=String(req.headers['x-ib-mac']||'');
 if(!/^[a-z0-9-]{3,40}$/.test(id)||!Number.isSafeInteger(ts)||Math.abs(Date.now()-ts)>60000||!/^[a-f0-9]{24,64}$/.test(nonce)||!/^[a-f0-9]{64}$/.test(mac))return null;
 const signed=id+'\n'+ts+'\n'+nonce;
 const perDevice=crypto.createHmac('sha256',KEY).update('IB09-device:'+id).digest();
 const check=crypto.createHmac('sha256',perDevice).update(signed).digest('hex');
 if(!crypto.timingSafeEqual(Buffer.from(check,'hex'),Buffer.from(mac,'hex')))return null;
 const key=id+':'+nonce;
 if(nonceSeen.has(key))return null;
 nonceSeen.set(key,Date.now());
 for(const [n,t] of nonceSeen)if(Date.now()-t>120000)nonceSeen.delete(n);
 return id;
}
server.on('upgrade',(req,socket,head)=>{
 if(req.url!=='/tunnel')return fail(socket,404,'Not Found');
 const id=check(req);
 if(!id)return fail(socket,401,'Unauthorized');
 let voucher=null;
 if(rights){
  try {
   voucher=rights.verify(req.headers['x-ib-voucher'],id);
  }catch(e){
   return fail(socket,403,'Voucher Rejected');
  }
 }
 if((clients.get(id)||0)>=4)return fail(socket,429,'Too Many Connections');
 wss.handleUpgrade(req,socket,head,ws=>{
  clients.set(id,(clients.get(id)||0)+1);
  wss.emit('connection',ws,req,id,voucher);
 });
});
async function resolvePublic(host){
 if(net.isIP(host)){
  if(!publicIp(host))throw Error('private target denied');
  return {address:host,family:net.isIP(host)};
 }
 if(typeof host!=='string'||host.length>253||!(/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/i.test(host)||net.isIP(host)))throw Error('invalid hostname');
 const records=await dns.lookup(host,{all:true});
 const eligible=records.find(x=>publicIp(x.address));
 if(!eligible)throw Error('no public address');
 return eligible;
}
wss.on('connection',(ws,req,id,voucher)=>{
 const debit=(n)=>rights?rights.spend(voucher,n):charge(id,n);
 let remote=null,established=false,closed=false,remainingTimer=null,udpSockets=new Set();
 const safeClose=(code=1000,reason='done')=>{
  if(closed)return;closed=true;
  clearInterval(remainingTimer);
  for(const d of udpSockets)try{d.close();}catch(e){}
  remote?.destroy();
  if(ws.readyState===ws.OPEN)ws.close(code,reason.slice(0,100));
 };
 const send=(msg)=>{if(ws.readyState===ws.OPEN)ws.send(JSON.stringify(msg));};
 ws.on('message',async(payload,binary)=>{
  try{
   if(binary){
    if(!established||!remote||remote.destroyed)throw Error('not connected');
    if(payload.length>65536)throw Error('frame limit');
    if(!debit(payload.length)){send({op:'quota',used:rights?rights.getSpent(voucher.voucherId):spend[id],limit:voucher?voucher.quotaBytes:LIMIT});safeClose(1008,'quota');return;}
    remote.write(payload);return;
   }
   const m=JSON.parse(String(payload));
   if(m.op==='balance'&&!established&&!remote){
     if(!rights||!voucher){send({op:'error',error:'no prepaid voucher'});return;}
     const spent=rights.getSpent(voucher.voucherId);
     send({op:'balance',voucherId:voucher.voucherId,spent,remaining:Math.max(0,voucher.quotaBytes-spent),quotaBytes:voucher.quotaBytes});
     return;
   }

   if(m.op==='connect'&&!established&&!remote){
     if(m.port!==443&&m.port!==80)throw Error('port restricted in lab');
     const a=await resolvePublic(m.host);
     remote=net.connect({host:a.address,port:m.port,family:a.family,timeout:8000});
     remote.on('connect',()=>{established=true;send({op:'connected',ipFamily:a.family,remaining:voucher?voucher.quotaBytes-rights.getSpent(voucher.voucherId):LIMIT-(spend[id]||0)});});
     remote.on('data',(chunk)=>{
       if(!debit(chunk.length)){send({op:'quota',used:rights?rights.getSpent(voucher.voucherId):spend[id],limit:voucher?voucher.quotaBytes:LIMIT});safeClose(1008,'quota');return;}
       if(ws.readyState===ws.OPEN){ws.send(chunk,{binary:true});if(ws.bufferedAmount>1024*1024)remote.pause();}
     });
     remainingTimer=setInterval(()=>{if(remote?.isPaused()&&ws.bufferedAmount<128*1024)remote.resume();},50);
     remote.on('end',()=>{send({op:'end'});safeClose();});
     remote.on('error',e=>{send({op:'error',error:e.code||'REMOTE'});safeClose(1011,'remote');});
     remote.on('timeout',()=>{send({op:'error',error:'remote timeout'});safeClose(1011,'timeout');});
     return;
   }
   if(m.op==='dns'&&typeof m.host==='string'&&!established&&!remote){
     const p=await resolvePublic(m.host);
     send({op:'dns',host:m.host,ipFamily:p.family,address:p.address});return;
   }
   // Experimental UDP relay restricted to DNS port 53 for this lab
   if(m.op==='udp53'&&!established&&!remote){
     if(m.rid!==undefined && (!Number.isSafeInteger(m.rid) || m.rid<1 || m.rid>2147483647))throw Error('invalid udp request id');
     if(!publicIp(m.host)||m.port!==53||typeof m.data!=='string'||m.data.length>2048)throw Error('invalid udp53 request');
     const bytes=Buffer.from(m.data,'base64');if(!bytes.length||bytes.length>1000)throw Error('udp53 packet invalid');
     if(!debit(bytes.length)){safeClose(1008,'quota');return;}
     const family=net.isIP(m.host);const d=dgram.createSocket(family==='6'?'udp6':'udp4');udpSockets.add(d);
     d.on('message',response=>{
       if(!debit(response.length)){safeClose(1008,'quota');return;}
       send({op:'udp53_reply',rid:m.rid,data:response.toString('base64')});
       d.close();udpSockets.delete(d);
     });
     d.on('error',e=>{send({op:'error',error:e.code||'UDP'});udpSockets.delete(d);d.close();});
     d.send(bytes,53,m.host);
     setTimeout(()=>{if(udpSockets.has(d)){send({op:'error',error:'udp timeout'});d.close();udpSockets.delete(d);}},3500);
     return;
   }
   throw Error('unknown protocol frame');
  }catch(e){send({op:'error',error:String(e.message||e)});safeClose(1008,'protocol');}
 });
 ws.on('close',()=>{clearInterval(remainingTimer);for(const d of udpSockets)try{d.close();}catch(e){}remote?.destroy();clients.set(id,Math.max(0,(clients.get(id)||1)-1));});
 ws.on('error',()=>{remote?.destroy();});
});
server.listen(PORT,'0.0.0.0',()=>console.log('IB09_GATEWAY_LISTENING port='+PORT));
process.on('SIGTERM',()=>server.close());
