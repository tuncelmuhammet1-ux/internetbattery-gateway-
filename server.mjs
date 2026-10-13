import http from 'node:http';
import {lookup} from 'node:dns/promises';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
import {readConfig, verifyHeaders, publicV4} from './auth.mjs';
import {upgradeWebSocket} from './ws.mjs';
import {makeAndroid013Gateway} from './android013.mjs';
import {verifierFromPem, GB} from './voucher.mjs';
import {makeWalletApi} from './wallet-api.mjs';
import {connectPostgresLedger} from './ledger.mjs';
import {createPairing} from './pairing.mjs';
import {runRemoteWssHttpsProbe} from './tools/wss-remote-probe.mjs';

const VERSION='0.15.0-lab';
const MAX_STREAMS=4;
const MAX_DATA=96*1024;
function publicHost(host) {return typeof host==='string' && host.length<=253 && host.includes('.') && host.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));}
function validId(id){return typeof id==='string' && /^[a-zA-Z0-9_-]{1,32}$/.test(id);}
function jsonResponse(res,status,obj){const data=JSON.stringify(obj);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Content-Length':Buffer.byteLength(data)});res.end(data);}
function closedUpgrade(socket,status){socket.end('HTTP/1.1 '+status+'\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');}
function validateBase64(b64) {return typeof b64==='string' && b64.length>0 && b64.length<=Math.ceil(MAX_DATA/3)*4 && /^[A-Za-z0-9+/]+={0,2}$/.test(b64) && b64.length%4===0;}

export function makeServer(env=process.env, hooks={}) {
  const config=readConfig(env);
  const ledger=hooks.ledger||null;
  const creditReady=Boolean(ledger&&env.IB_CREDIT_DB_ENABLED==='1' && env.IB_ISSUER_PUBLIC_KEY_PEM && env.IB_VOUCHER_GATEWAY_ID);
  const verifyVoucher=creditReady?verifierFromPem(env.IB_ISSUER_PUBLIC_KEY_PEM,{gatewayId:env.IB_VOUCHER_GATEWAY_ID}):null;
  const android013=makeAndroid013Gateway(config,{lookup:hooks.android013Lookup,connect:hooks.android013Connect,
    ledger:creditReady?ledger:null,verifyVoucher});
  const android013Enabled=env.IB_ANDROID013_COMPAT==='1';
  const walletReady=Boolean(creditReady&&env.IB_WALLET_HTTP_ENABLED==='1'&&env.IB_ISSUER_PRIVATE_KEY_PEM);
  const walletApi=makeWalletApi(config,{ledger,enabled:walletReady,privateKeyPem:env.IB_ISSUER_PRIVATE_KEY_PEM,
    gatewayId:env.IB_VOUCHER_GATEWAY_ID});
  // Database balance is research credit, not a prepaid cellular data plan.
  const pairing=createPairing(config,{enabled:env.IB_PAIRING_ENABLED==='1',code:hooks.pairingCode,emit:hooks.pairingEmit||console.log});
  const probeStatus={state:env.IB_REMOTE_WSS_SELFTEST==='1'?'pending':'disabled'};
  const nonceCache=new Map();
  const maxAge=2*60*1000;
  let openSessions=0;
  const server=http.createServer((req,res)=>{
    if(req.url==='/pair'||req.url==='/v1/pair/redeem'){void pairing(req,res).catch(()=>jsonResponse(res,503,{error:'pairing_unavailable'}));return;}
    if(req.url==='/wallet'||req.url?.startsWith('/v1/wallet/')){
      void Promise.resolve(walletApi(req,res)).catch(()=>jsonResponse(res,503,{error:'wallet_internal_error'}));return;
    }
    if(req.method!=='GET')return jsonResponse(res,405,{error:'method_not_allowed'});
    if(req.url==='/healthz')return jsonResponse(res,200,{service:'internetbattery-gateway',version:VERSION,status:'alive'});
    if(req.url==='/selftestz')return jsonResponse(res,200,{...probeStatus,physicalAndroidVerified:false,operatorGbStored:false});
    if(req.url==='/readyz')return jsonResponse(res,config?200:503,{ready:!!config,mode:'lab_ws1',android013LabCompatibility:android013Enabled,
      creditLedgerReady:creditReady,ib1VoucherSupport:creditReady,walletPortalReady:walletReady,pairingPortalConfigured:env.IB_PAIRING_ENABLED==='1',
      labSessionByteCap:config?.limit||0,requiresActiveNetwork:true});
    return jsonResponse(res,404,{error:'not_found'});
  });
  server.on('upgrade',(req,socket,head)=>{
    if(req.url==='/tunnel'){if(!android013Enabled){closedUpgrade(socket,'404 Not Found');return;}android013.upgrade(req,socket,head);return;}
    if(req.url!=='/ws'){closedUpgrade(socket,'404 Not Found');return;}
    if(!config){closedUpgrade(socket,'503 Service Unavailable');return;}
    if(openSessions>=50){closedUpgrade(socket,'503 Service Unavailable');return;}
    const verification=verifyHeaders(config,req.headers);
    if(!verification.ok){closedUpgrade(socket,'401 Unauthorized');return;}
    const now=Date.now();
    for(const [key,expires] of nonceCache)if(expires<now)nonceCache.delete(key);
    if(nonceCache.has(verification.nonce) || nonceCache.size>=50000){closedUpgrade(socket,'401 Unauthorized');return;}
    nonceCache.set(verification.nonce,now+maxAge);
    const streams=new Map(),pending=new Set(); let used=0, active=true,dnsQueries=0;openSessions++;
    const cleanup=()=>{if(!active)return;active=false;openSessions--;for(const stream of streams.values())stream.destroy();streams.clear();pending.clear();};
    const message=(msg,ws)=>{void processMessage(msg,ws).catch(()=>{ws.sendJson({t:'error',error:'internal_failure'});});};
    async function processMessage(msg,ws){
      if(!msg || typeof msg!=='object' || Array.isArray(msg))return ws.sendJson({t:'error',error:'invalid_message'});
      const t=msg.t, id=msg.id;
      if(t==='status')return ws.sendJson({t:'status',used,limit:config.limit,remaining:config.limit-used});
      if(!validId(id))return ws.sendJson({t:'error',error:'invalid_stream_id'});
      const fail=(reason)=>ws.sendJson({t:'error',id,error:reason});
      if(t==='close'){const stream=streams.get(id); if(stream){streams.delete(id);stream.destroy();}return ws.sendJson({t:'closed',id});}
      if(t==='dns'){
        if(++dnsQueries>50)return fail('dns_query_limit');
        if(!publicHost(msg.host))return fail('invalid_host');
        let ips=[];
        try { ips=(await lookup(msg.host,{family:4,all:true})).map(x=>x.address).filter(publicV4).slice(0,8); } catch {return fail('dns_failure');}
        return ws.sendJson({t:'dns',id,addrs:ips});
      }
      if(t==='open'){
        if(streams.has(id) || pending.has(id))return fail('already_open');
        if(streams.size+pending.size>=MAX_STREAMS)return fail('too_many_streams');
        if(used>=config.limit)return fail('quota_exhausted');
        if(!publicHost(msg.host)|| ![80,443].includes(msg.port))return fail('destination_blocked');
        pending.add(id);
        let addresses=[];
        try { addresses=(await lookup(msg.host,{family:4,all:true})).map(x=>x.address).filter(publicV4); } catch{pending.delete(id);return fail('dns_failure');}
        pending.delete(id);
        if(!active || ws.closed)return;
        if(addresses.length===0)return fail('destination_blocked');
        const upstream=net.connect({host:addresses[0],port:msg.port,timeout:10000});
        streams.set(id,upstream);
        upstream.on('connect',()=>{if(!ws.closed)ws.sendJson({t:'open',id});});
        upstream.on('data',data=>{
          if(ws.closed || !active) {upstream.destroy();return;}
          const remaining=config.limit-used;
          if(remaining<=0){upstream.destroy();return;}
          const part=data.subarray(0,Math.min(MAX_DATA,remaining));
          used+=part.length;
          if(part.length && !ws.sendJson({t:'data',id,b64:part.toString('base64')})){
            upstream.pause();ws.onDrain(()=>{if(!upstream.destroyed)upstream.resume();});
          }
          if(data.length>part.length || used>=config.limit)upstream.destroy();
        });
        upstream.on('error',()=>{if(!ws.closed)fail('upstream_failure');});
        upstream.on('close',()=>{streams.delete(id);if(!ws.closed)ws.sendJson({t:'closed',id});});
        return;
      }
      if(t==='data'){
        const stream=streams.get(id);
        if(!stream || stream.destroyed)return fail('stream_not_open');
        if(!validateBase64(msg.b64))return fail('invalid_data');
        const data=Buffer.from(msg.b64,'base64');
        if(data.toString('base64')!==msg.b64 || data.length===0 || data.length>MAX_DATA)return fail('invalid_data');
        if(data.length>config.limit-used){stream.destroy();return fail('quota_exhausted');}
        used+=data.length;
        stream.write(data);
        if(used>=config.limit)stream.end();
        return;
      }
      return fail('unknown_command');
    }
    const ws=upgradeWebSocket(req,socket,head,message,cleanup);
    if(!ws){cleanup();return;}
    ws.sendJson({t:'hello',version:VERSION,mode:'lab_ws1',quotaBytes:config.limit,ib1VoucherSupport:false});
  });
  server.on('close',()=>{nonceCache.clear();});
  server.recordProbeResult=result=>{Object.assign(probeStatus,{state:result.ok?'success':'failure',checkedAt:new Date().toISOString(),mode:result.mode||'wss_tcp_tls_https',httpStatus:result.httpStatus||null,error:result.error||null,elapsedMs:result.durationMs||null});};
  hooks.onCreated?.(server);
  return server;
}

if(process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1]){
  async function boot(){
    const env=process.env;
    let ledger=null;
    if(env.IB_CREDIT_DB_ENABLED==='1'){
      ledger=await connectPostgresLedger(env.DATABASE_URL,{ssl:env.IB_POSTGRES_SSL==='1'});
      // Idempotent operator-originated LAB packages: test rights, not earned carrier data.
      // Each grant ID is constant, so restarting/redeploying never mints duplicates.
      if(env.IB_LAB_SEED_PACKAGES){
        const options=env.IB_LAB_SEED_PACKAGES.split(',').map(x=>Number(x.trim()));
        if(options.some(x=>![1,5,10].includes(x))||new Set(options).size!==options.length)throw Error('invalid_lab_seed_packages');
        for(const gb of options){await ledger.grant(env.IB_DEVICE_ID,gb*GB,`pilot20261013_${gb}gb`,'lab_admin');}
      }
    }
    const port=Number(env.PORT||3000);
    const server=makeServer(env,{ledger});
    server.listen(port,'0.0.0.0',()=>{
      console.log(JSON.stringify({service:'internetbattery-gateway',version:VERSION,port,lab:true,creditLedgerConfigured:!!ledger}));
      if(env.IB_REMOTE_WSS_SELFTEST==='1'){
        // Test the actual Render public TLS ingress, authenticated WSS, TCP relay,
        // certificate-checked TLS and external HTTPS response without a physical phone.
        setTimeout(()=>{
          void runRemoteWssHttpsProbe({url:'wss://internetbattery-gateway.onrender.com/tunnel',config:readConfig(env)})
            .then(value=>{server.recordProbeResult(value);console.log('IB_REMOTE_LIVE_PROBE_OK '+JSON.stringify(value));})
            .catch(err=>{const reason=String(err?.message||'unknown').slice(0,100);server.recordProbeResult({ok:false,error:reason});console.warn('IB_REMOTE_LIVE_PROBE_FAILED '+reason);});
        },3500).unref?.();
      }
    });
    process.on('SIGTERM',()=>server.close());
  }
  boot().catch(e=>{console.error('IB_GATEWAY_STARTUP_FAILED',e.code||e.message?.split(':')[0]||'configuration_failure');process.exitCode=1;});
}
