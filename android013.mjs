import {createHmac, timingSafeEqual} from 'node:crypto';
import {lookup as lookupDns} from 'node:dns/promises';
import dgram from 'node:dgram';
import net from 'node:net';
import {publicV4} from './auth.mjs';
import {upgradeWebSocket} from './ws.mjs';

/*
 * Android 0.13 compatibility adapter for the verified WssCredentials.kt and
 * WssSocksBridge.kt wire format. It is an authenticated and QUOTA-LIMITED lab
 * transport. It does NOT redeem IB1 vouchers: there is no durable credit ledger
 * on the free Render filesystem. Any IB1 header fails closed with HTTP 403.
 */
const MAX_BINARY=65536;
const MAX_UDP=1000;
const NONCE_TTL_MS=120000;
const WS_IDLE_MS=10*60*1000;
const DNS_LIMIT=50;
const UDP_LIMIT=25;
const domain=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const closed=(socket,code,label)=>{
  socket.end(`HTTP/1.1 ${code} ${label}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
};

export function android013Signature(config,id,timestamp,nonce){
  if(!config)throw new Error('gateway not configured');
  const deviceKey=createHmac('sha256',config.key).update('IB09-device:'+id).digest();
  return createHmac('sha256',deviceKey).update(`${id}\n${timestamp}\n${nonce}`).digest('hex');
}

export function verifyAndroid013Headers(config,headers,now=Date.now()){
  if(!config)return {ok:false,reason:'unconfigured'};
  const id=headers['x-ib-id'],ts=headers['x-ib-ts'],nonce=headers['x-ib-nonce'],mac=headers['x-ib-mac'];
  if(typeof id!=='string' || id!==config.device || !/^[a-z0-9-]{3,40}$/.test(id) ||
      typeof ts!=='string' || !/^\d{13}$/.test(ts) ||
      typeof nonce!=='string'||!/^[a-f0-9]{24,64}$/.test(nonce) ||
      typeof mac!=='string'||!/^[a-f0-9]{64}$/.test(mac))return {ok:false,reason:'invalid'};
  if(Math.abs(now-Number(ts))>60000)return {ok:false,reason:'timestamp'};
  const expected=Buffer.from(android013Signature(config,id,ts,nonce),'hex');
  if(!timingSafeEqual(expected,Buffer.from(mac,'hex')))return {ok:false,reason:'signature'};
  return {ok:true,device:id,nonce:id+':'+nonce};
}

export function makeAndroid013Gateway(config,options={}){
  const dnsLookup=options.lookup||lookupDns;
  const connectTcp=options.connect||net.connect;
  const nonceSeen=new Map();
  const sessions=new Map();
  let debitTotal=0;
  let connections=0;
  async function resolvePublic(host){
    if(typeof host!=='string'||host.length>253)throw Error('destination_blocked');
    if(net.isIP(host)){
      if(net.isIP(host)!==4 || !publicV4(host))throw Error('destination_blocked');
      return host;
    }
    if(!domain.test(host))throw Error('invalid_domain');
    const records=await dnsLookup(host,{family:4,all:true});
    const found=records.find(r=>r.family===4&&publicV4(r.address));
    if(!found)throw Error('destination_blocked');
    return found.address;
  }
  function charge(bytes){
    if(!Number.isSafeInteger(bytes)||bytes<0 || debitTotal+bytes>config.limit)return false;
    debitTotal+=bytes;
    return true;
  }
  function upgrade(req,socket,head){
    if(!config){closed(socket,503,'Service Unavailable');return;}
    if(req.headers['x-ib-voucher']!==undefined){closed(socket,403,'Voucher Not Enabled');return;}
    const auth=verifyAndroid013Headers(config,req.headers);
    if(!auth.ok){closed(socket,401,'Unauthorized');return;}
    const now=Date.now();
    for(const [nonce,expiry] of nonceSeen){if(expiry<now)nonceSeen.delete(nonce);}
    if(nonceSeen.has(auth.nonce)||nonceSeen.size>=50000){closed(socket,401,'Unauthorized');return;}
    if(connections>=4 || debitTotal>=config.limit){closed(socket,429,'Too Many Requests');return;}
    nonceSeen.set(auth.nonce,now+NONCE_TTL_MS);
    connections++;
    let ws=null,remote=null,closedSession=false,established=false,pendingConnect=false;
    let dnsCount=0,udpCount=0,activeDns=0;
    const udpSockets=new Set();
    const timer=setTimeout(()=>{ws?.close(1001,'lab_time_limit');},WS_IDLE_MS);
    timer.unref?.();
    const cleanup=()=>{
      if(closedSession)return;
      closedSession=true;connections--;
      clearTimeout(timer);
      remote?.destroy();remote=null;
      for(const d of udpSockets){try{d.close();}catch{}}
      udpSockets.clear();
    };
    const send=(obj)=>{if(!closedSession&&!ws?.closed)ws?.sendJson(obj);};
    const failure=(kind)=>{send({op:'error',error:kind});};
    const stop=(kind)=>{send({op:'quota',error:kind,limit:config.limit,used:debitTotal});ws?.close(1008,kind);};
    async function onCommand(message,connection){
      if(closedSession)return;
      if(Buffer.isBuffer(message)){
        if(!established||!remote||remote.destroyed||message.length<1||message.length>MAX_BINARY){failure('not_connected');connection.close(1008,'invalid_data');return;}
        if(!charge(message.length)){stop('quota_exhausted');return;}
        // An outbound socket may buffer writes briefly; bytes remain capped per process.
        remote.write(message);
        return;
      }
      if(!message||typeof message!=='object'||Array.isArray(message)){failure('invalid_frame');return;}
      const op=message.op;
      if(op==='balance'){
        failure('ib1_not_enabled_on_ephemeral_gateway');
        return;
      }
      if(op==='dns'){
        if(++dnsCount>DNS_LIMIT||activeDns>=5){failure('dns_query_limit');return;}
        activeDns++;
        try{
          const address=await resolvePublic(message.host);
          send({op:'dns',host:message.host,address,ipFamily:4});
        }catch(e){failure(e.message||'dns_failure');}
        finally{activeDns--;}
        return;
      }
      if(op==='connect'){
        if(remote||pendingConnect||established){failure('already_connected');return;}
        if(message.port!==80 && message.port!==443){failure('destination_blocked');return;}
        pendingConnect=true;
        let address;
        try{address=await resolvePublic(message.host);}catch(e){pendingConnect=false;failure(e.message||'destination_blocked');return;}
        if(closedSession)return;
        const sock=connectTcp({host:address,port:message.port,family:4,timeout:8000});
        remote=sock;
        sock.on('connect',()=>{if(closedSession)return;established=true;send({op:'connected',ipFamily:4,remaining:config.limit-debitTotal});});
        sock.on('data',data=>{
          if(closedSession||!established)return;
          if(!charge(data.length)){stop('quota_exhausted');return;}
          if(!connection.sendBinary(data)){
            sock.pause();connection.onDrain(()=>{if(!sock.destroyed)sock.resume();});
          }
        });
        sock.on('end',()=>{send({op:'end'});connection.close(1000,'remote_end');});
        sock.on('timeout',()=>{failure('remote_timeout');connection.close(1011,'remote_timeout');});
        sock.on('error',()=>{failure('upstream_failure');connection.close(1011,'remote_error');});
        sock.on('close',()=>{established=false;remote=null;pendingConnect=false;});
        return;
      }
      if(op==='udp53'){
        if(++udpCount>UDP_LIMIT||udpSockets.size>=3){failure('udp_query_limit');return;}
        if(established||pendingConnect||remote||!Number.isSafeInteger(message.rid)||message.rid<1||message.rid>2147483647||
           typeof message.host!=='string'||!publicV4(message.host)||message.port!==53||
           typeof message.data!=='string'||message.data.length>1400 || !/^[A-Za-z0-9+/]+={0,2}$/.test(message.data)){
          failure('invalid_udp53');return;
        }
        const bytes=Buffer.from(message.data,'base64');
        if(bytes.length<1||bytes.length>MAX_UDP||bytes.toString('base64')!==message.data){failure('invalid_udp53');return;}
        if(!charge(bytes.length)){stop('quota_exhausted');return;}
        const udp=dgram.createSocket('udp4');udpSockets.add(udp);
        const deadline=setTimeout(()=>{failure('udp_timeout');udp.close();},3500);
        deadline.unref?.();
        udp.on('message',reply=>{
          clearTimeout(deadline);
          if(!charge(reply.length)){stop('quota_exhausted');}
          else send({op:'udp53_reply',rid:message.rid,data:reply.toString('base64')});
          udp.close();
        });
        udp.on('error',()=>{clearTimeout(deadline);failure('udp_failure');udp.close();});
        udp.on('close',()=>{clearTimeout(deadline);udpSockets.delete(udp);});
        udp.send(bytes,53,message.host);
        return;
      }
      failure('unknown_op');
    }
    const handler=(message,connection)=>{void onCommand(message,connection).catch(()=>{failure('internal_failure');connection.close(1011,'error');});};
    ws=upgradeWebSocket(req,socket,head,handler,cleanup);
    if(!ws)cleanup();
  }
  return {upgrade,getStatus:()=>({activeSessions:connections,usedBytes:debitTotal,limitBytes:config?.limit||0,protocol:'android_013_lab',ib1VoucherSupport:false})};
}
