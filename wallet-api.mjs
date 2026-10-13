import {createHmac, createHash, createPrivateKey, createPublicKey, randomBytes, timingSafeEqual} from 'node:crypto';
import {makeIB1, GB, DENOMINATIONS} from './voucher.mjs';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';

const textBody=readFileSync(join(dirname(fileURLToPath(import.meta.url)),'wallet.html'),'utf8');
const headerNames=['x-ib-id','x-ib-ts','x-ib-nonce','x-ib-mac'];
const sha=body=>createHash('sha256').update(body).digest('hex');
export const walletDeviceKey=(config)=>createHmac('sha256',config.key).update('IB09-device:'+config.device).digest();
export function walletMac(config,id,ts,nonce,method,path,body){
  return createHmac('sha256',walletDeviceKey(config)).update(`${id}\n${ts}\n${nonce}\n${method}\n${path}\n${sha(body)}`).digest('hex');
}
export function verifyWalletRequest(config,headers,method,path,body,now=Date.now()){
  if(!config||headerNames.some(k=>typeof headers[k]!=='string'))return false;
  const [id,ts,nonce,mac]=headerNames.map(k=>headers[k]);
  if(id!==config.device||!/^[a-z0-9-]{3,40}$/.test(id)||!/^[0-9]{13}$/.test(ts)||
    !/^[a-f0-9]{24,64}$/.test(nonce)||!/^[a-f0-9]{64}$/.test(mac)||
    Math.abs(now-Number(ts))>60000)return false;
  const expected=Buffer.from(walletMac(config,id,ts,nonce,method,path,body),'hex');
  return timingSafeEqual(expected,Buffer.from(mac,'hex'));
}
function answer(res,status,obj){
  const body=JSON.stringify(obj);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Length':Buffer.byteLength(body)});res.end(body);
}
async function readBody(req){
  let b=Buffer.alloc(0);
  for await(const c of req){b=Buffer.concat([b,c]);if(b.length>2048)throw Error('oversized_request');}
  if(b.length<2)throw Error('empty_request');
  return b.toString('utf8');
}
export function makeWalletApi(config,{ledger,privateKeyPem,gatewayId,enabled=false,now=()=>Date.now()}={}){
  let privateKey=null;
  if(enabled){
    if(!ledger || typeof privateKeyPem!=='string'||!gatewayId)throw Error('wallet_api_requires_ledger_and_issuer');
    privateKey=createPrivateKey(privateKeyPem.replace(/\\n/g,'\n'));
    if(privateKey.asymmetricKeyType!=='ed25519')throw Error('invalid_wallet_issuer');
  }
  return async(req,res)=>{
    if(req.method==='GET'&&req.url==='/wallet'){
      if(!enabled)return answer(res,503,{error:'wallet_not_configured'});
      return res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store',
        'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY'}).end(textBody);
    }
    if(!req.url?.startsWith('/v1/wallet/'))return false;
    if(!enabled)return answer(res,503,{error:'wallet_not_configured'});
    if(req.method!=='POST')return answer(res,405,{error:'post_required'});
    if(!['/v1/wallet/balance','/v1/wallet/issue'].includes(req.url))return answer(res,404,{error:'unknown_route'});
    let body,request;
    try{body=await readBody(req);request=JSON.parse(body);}catch{return answer(res,400,{error:'invalid_json_body'});}
    if(!request||typeof request!=='object'||Array.isArray(request))return answer(res,400,{error:'invalid_request'});
    if(!verifyWalletRequest(config,req.headers,'POST',req.url,body,now()))return answer(res,401,{error:'invalid_signature'});
    try{
      if(!await ledger.claimNonce(config.device,req.headers['x-ib-nonce'],now()+120000))return answer(res,409,{error:'replay_rejected'});
      const w=await ledger.wallet(config.device);
      if(req.url==='/v1/wallet/balance')return answer(res,200,{kind:'research_rights',creditUnit:'byte',...w,persistentUntil:'database_expiry',operatorInternetGb:false});
      const gb=request.packageGb;
      if(![1,5,10].includes(gb))return answer(res,422,{error:'choose_1_5_or_10_gb'});
      const amount=gb*GB;
      if(w.availableBytes<amount)return answer(res,409,{error:'insufficient_research_balance',availableBytes:w.availableBytes});
      const issuedAtMs=now();
      const expiresAtMs=issuedAtMs+24*60*60*1000;
      const voucher=makeIB1({voucherId:randomBytes(9).toString('base64url'),holderId:config.device,gatewayId,quotaBytes:amount,issuedAtMs,expiresAtMs},privateKey);
      if(voucher.length>255)throw Error('android_013_voucher_too_long');
      return answer(res,200,{kind:'research_rights',voucher,issuedBytes:amount,expiresAtMs,sessionLimitBytes:config.limit,warning:'This is NOT a mobile operator data package'});
    }catch(e){return answer(res,503,{error:'wallet_unavailable'});}
  };
}
