// Temporary, single-use lab pairing via Render owner's protected logs. No master key or
// derived HMAC key is present in the public web page, GitHub repo or APK.
import {randomBytes,createHash,timingSafeEqual,createHmac} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';

const html=readFileSync(join(dirname(fileURLToPath(import.meta.url)),'pair.html'),'utf8');
const SHA256=x=>createHash('sha256').update(x).digest();
const timeoutMs=30*60*1000;
const ID_PATTERN=/^[a-z0-9-]{3,40}$/;
function reply(res,status,payload){
  const data=JSON.stringify(payload);
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
    'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
    'Content-Length':Buffer.byteLength(data)});
  res.end(data);
}
export function createPairing(config,{enabled=false,now=()=>Date.now(),code,emit=console.log}={}){
  const valid=Boolean(enabled&&config&&ID_PATTERN.test(config.device));
  const secret=code??randomBytes(16).toString('base64url'); // 128-bit, time-limited
  if(valid&&!/^[A-Za-z0-9_-]{22}$/.test(secret))throw Error('bad_pair_code');
  const expected=SHA256(secret);const expires=now()+timeoutMs;
  let consumed=false,attempts=0,windowStart=now();
  if(valid)emit('IB_PAIR_ONCE_CODE='+secret+' (use only at /pair; expires in 30 minutes; never paste into chat)');
  const available=()=>valid&&!consumed&&now()<expires;
  return async function handlePairing(req,res){
    if(req.url!=='/pair'&&req.url!=='/v1/pair/redeem')return false;
    if(!valid)return reply(res,503,{error:'pairing_disabled'});
    if(req.url==='/pair'){
      if(req.method!=='GET')return reply(res,405,{error:'GET_required'});
      res.writeHead(available()?200:410,{'Content-Type':'text/html; charset=utf-8',
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY',
        'X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"});
      return res.end(html);
    }
    if(req.method!=='POST')return reply(res,405,{error:'POST_required'});
    if(!available())return reply(res,410,{error:'pairing_expired_or_used'});
    // Only same-origin browser access is permitted. Direct HTTPS clients may omit Origin.
    if(req.headers.origin){
      try {const origin=new URL(req.headers.origin);
        if(origin.protocol!=='https:'||origin.host!==req.headers.host)return reply(res,403,{error:'origin_rejected'});
      }catch{return reply(res,403,{error:'origin_rejected'});}
    }
    const chunks=[];let length=0;
    try {for await(const part of req){length+=part.length;if(length>256)throw Error('too_large');chunks.push(part);}}
    catch{return reply(res,400,{error:'invalid_body'});}
    let input;
    try{input=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return reply(res,400,{error:'invalid_json'});}
    const text=input?.code;
    if(typeof text!=='string'||!/^[A-Za-z0-9_-]{22}$/.test(text))return reply(res,401,{error:'pairing_denied'});
    if(now()-windowStart>60*1000){windowStart=now();attempts=0;}
    if(++attempts>30)return reply(res,429,{error:'rate_limit'});
    if(!timingSafeEqual(expected,SHA256(text)))return reply(res,401,{error:'pairing_denied'});
    consumed=true;
    const deviceKey=createHmac('sha256',config.key).update('IB09-device:'+config.device).digest('hex');
    return reply(res,200,{deviceId:config.device,deviceKey,wssUrl:'wss://internetbattery-gateway.onrender.com/tunnel',lab:true,
      notice:'Cihaz anahtarı gizlidir; halka açık ortamlarda paylaşmayın. Operatör GB hakkı değildir.'});
  };
}
