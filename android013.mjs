import {createHmac, timingSafeEqual, randomUUID} from 'node:crypto';
import {lookup as lookupDns} from 'node:dns/promises';
import dgram from 'node:dgram';
import net from 'node:net';
import {publicV4} from './auth.mjs';
import {upgradeWebSocket} from './ws.mjs';

/*
 * Android 0.13 compatibility adapter for the verified WssCredentials.kt and
 * WssSocksBridge.kt wire format. It is an authenticated and QUOTA-LIMITED lab
 * transport. Only signed IB1 vouchers can access durable spending when a
 * PostgreSQL ledger and trusted Ed25519 issuer are configured. Unprovisioned
 * or unverifiable vouchers fail closed; never count unsigned traffic as credit.
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
  const ledger=options.ledger||null;
  const verifyVoucher=options.verifyVoucher||null;
  const creditReady=Boolean(ledger&&verifyVoucher);
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
  function chargeTrial(bytes){
    if(!Number.isSafeInteger(bytes)||bytes<0 || debitTotal+bytes>config.limit)return false;
    debitTotal+=bytes;
    return true;
  }
  function upgrade(req,socket,head){
    if(!config){closed(socket,503,'Service Unavailable');return;}
    const auth=verifyAndroid013Headers(config,req.headers);
    if(!auth.ok){closed(socket,401,'Unauthorized');return;}
    const now=Date.now();
    for(const [nonce,expiry] of nonceSeen){if(expiry<now)nonceSeen.delete(nonce);}
    if(nonceSeen.has(auth.nonce)||nonceSeen.size>=50000){closed(socket,401,'Unauthorized');return;}
    const rawVoucher=req.headers['x-ib-voucher'];
    if(Array.isArray(rawVoucher)){closed(socket,403,'Voucher Rejected');return;}
    let voucher=null;
    if(rawVoucher!==undefined){
      if(!creditReady){closed(socket,503,'Credit Ledger Unavailable');return;}
      try{voucher=verifyVoucher(rawVoucher,auth.device);}catch{closed(socket,403,'Voucher Rejected');return;}
    }
    if(connections>=4 || (!voucher && debitTotal>=config.limit)){closed(socket,429,'Too Many Requests');return;}
    nonceSeen.set(auth.nonce,now+NONCE_TTL_MS);
    // Voucher admission first ensures that an unavailable database can never silently
    // downgrade a signed voucher to the unmetered transport.
    if(voucher){
      void ledger.balance(voucher).then(balance=>{
        if(socket.destroyed)return;
        beginSession(req,socket,head,{voucher,balance});
      }).catch(()=>{if(!socket.destroyed)closed(socket,503,'Credit Ledger Unavailable');});
    }else beginSession(req,socket,head,{voucher:null,balance:null});
  }
  function beginSession(req,socket,head,{voucher,balance}){
    connections++;
    const sessionId=randomUUID();
    let sessionUsed=0;
    let ws=null,remote=null,closedSession=false,established=false,pendingConnect=false;
    let work=Promise.resolve();
    const serial=(fn)=>{work=work.then(fn,fn);return work;};
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
    const stop=(kind)=>{
      send({op:'quota',error:kind,limit:config.limit,used:sessionUsed,ib1VoucherSupport:creditReady});
      ws?.close(1008,kind);
    };
    // Per-connection lab transport cap remains 5 MiB by default even for a
    // genuine 1/5/10 GB rights token, to avoid unlimited outbound relay abuse.
    async function charge(bytes,direction){
      if(!Number.isSafeInteger(bytes)||bytes<1||bytes>MAX_BINARY)return false;
      if(voucher){
        if(sessionUsed+bytes>config.limit)return false;
        try{
          const r=await ledger.spend(voucher,bytes,{direction,sessionId});
          if(!r.accepted)return false;
          sessionUsed+=bytes;balance=r;return true;
        }catch{stop('credit_ledger_unavailable');return false;}
      }
      if(!chargeTrial(bytes))return false;
      sessionUsed+=bytes;return true;
    }
    async function onCommand(message,connection){
      if(closedSession)return;
      if(Buffer.isBuffer(message)){
        if(!established||!remote||remote.destroyed||message.length<1||message.length>MAX_BINARY){failure('not_connected');connection.close(1008,'invalid_data');return;}
        if(!await charge(message.length,'uplink')){stop('quota_exhausted');return;}
        // An outbound socket may buffer writes briefly; bytes remain capped per process.
        remote.write(message);
        return;
      }
      if(!message||typeof message!=='object'||Array.isArray(message)){failure('invalid_frame');return;}
      const op=message.op;
      if(op==='balance'){
        if(!voucher){failure('ib1_voucher_required');return;}
        try{
          balance=await ledger.balance(voucher);
          send({op:'balance',voucherId:voucher.voucherId,spent:balance.spent,remaining:balance.remaining,quotaBytes:balance.quotaBytes});
        }catch{stop('credit_ledger_unavailable');}
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
        sock.on('connect',()=>{if(closedSession)return;established=true;
          send({op:'connected',ipFamily:4,remaining:voucher?balance.remaining:config.limit-debitTotal});});
        sock.on('data',data=>{
          if(closedSession||!established)return;
          sock.pause();
          void serial(async()=>{
            if(closedSession)return;
            // Frames larger than the credit accounting maximum are split.
            for(let off=0;off<data.length;off+=MAX_BINARY){
              const part=data.subarray(off,Math.min(data.length,off+MAX_BINARY));
              if(!await charge(part.length,'downlink')){stop('quota_exhausted');return;}
              if(!connection.sendBinary(part)){
                connection.onDrain(()=>{if(!sock.destroyed&&!closedSession)sock.resume();});
                return;
              }
            }
            if(!sock.destroyed&&!closedSession)sock.resume();
          }).catch(()=>stop('credit_ledger_unavailable'));
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
        if(!await charge(bytes.length,'dns_uplink')){stop('quota_exhausted');return;}
        const udp=dgram.createSocket('udp4');udpSockets.add(udp);
        const deadline=setTimeout(()=>{failure('udp_timeout');udp.close();},3500);
        deadline.unref?.();
        udp.on('message',reply=>{
          clearTimeout(deadline);
          void serial(async()=>{
            if(closedSession)return;
            if(!await charge(reply.length,'dns_downlink')){stop('quota_exhausted');return;}
            send({op:'udp53_reply',rid:message.rid,data:reply.toString('base64')});
          }).catch(()=>stop('credit_ledger_unavailable'));
          udp.close();
        });
        udp.on('error',()=>{clearTimeout(deadline);failure('udp_failure');udp.close();});
        udp.on('close',()=>{clearTimeout(deadline);udpSockets.delete(udp);});
        udp.send(bytes,53,message.host);
        return;
      }
      failure('unknown_op');
    }
    const handler=(message,connection)=>{
      void serial(()=>onCommand(message,connection)).catch(()=>{failure('internal_failure');connection.close(1011,'error');});
    };
    ws=upgradeWebSocket(req,socket,head,handler,cleanup);
    if(!ws)cleanup();
  }
  return {upgrade,getStatus:()=>({activeSessions:connections,trialUsedBytes:debitTotal,sessionLimitBytes:config?.limit||0,protocol:'android_013_lab',ib1VoucherSupport:creditReady})};
}
