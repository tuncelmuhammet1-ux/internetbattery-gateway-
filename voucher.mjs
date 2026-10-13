import {createPublicKey, createPrivateKey, verify, sign, createHash, createHmac, createPrivateKey as privateKey, createPublicKey as publicKey} from 'node:crypto';

const SAFE_ID=/^[a-zA-Z0-9_-]{1,100}$/;
const NUM=/^(0|[1-9][0-9]*)$/;
const URL64=/^[a-zA-Z0-9_-]+$/;
const MAX_BYTES=10_000_000_000; // decimal 10 GB; not cellular-operator allowance
export const GB=1_000_000_000;
export const DENOMINATIONS=[GB, 5*GB, 10*GB];

const canonical=(value)=>Buffer.from(value,'base64url').toString('base64url')===value;
const assertId=(v,name)=>{if(typeof v!=='string'||!SAFE_ID.test(v))throw Error('invalid_'+name);};

export function decodeIB1(raw){
  if(typeof raw!=='string'||!raw.startsWith('IB1.')||raw.length<80||raw.length>512)throw Error('invalid_voucher_format');
  const data=raw.slice(4);
  if(!URL64.test(data)||!canonical(data))throw Error('invalid_voucher_encoding');
  const b=Buffer.from(data,'base64url');
  const body=b.toString('utf8');
  if(!Buffer.from(body,'utf8').equals(b))throw Error('invalid_utf8');
  const fields=body.split('|');
  if(fields.length!==7)throw Error('invalid_voucher_fields');
  const [voucherId,holderId,gatewayId,q,issued,expires,signature]=fields;
  assertId(voucherId,'voucher_id');assertId(holderId,'holder_id');assertId(gatewayId,'gateway_id');
  if(![q,issued,expires].every(x=>NUM.test(x)))throw Error('invalid_voucher_numbers');
  if(!URL64.test(signature)||!canonical(signature))throw Error('invalid_signature');
  const sig=Buffer.from(signature,'base64url');
  const quotaBytes=Number(q),issuedAtMs=Number(issued),expiresAtMs=Number(expires);
  if(!Number.isSafeInteger(quotaBytes)||quotaBytes<1||quotaBytes>MAX_BYTES)throw Error('invalid_voucher_quota');
  if(!Number.isSafeInteger(issuedAtMs)||!Number.isSafeInteger(expiresAtMs)||issuedAtMs<=0||expiresAtMs<=issuedAtMs||expiresAtMs-issuedAtMs>86_400_000)throw Error('invalid_voucher_window');
  if(sig.length!==64)throw Error('invalid_signature_length');
  const signedPayload=fields.slice(0,6).join('|');
  const fingerprint=createHash('sha256').update(signedPayload+'\n'+signature).digest('hex');
  return {voucherId,holderId,gatewayId,quotaBytes,issuedAtMs,expiresAtMs,signature,fingerprint,signedPayload};
}

export function verifierFromPem(pem,{gatewayId,now=()=>Date.now()}={}){
  assertId(gatewayId,'gateway_id');
  if(!pem||typeof pem!=='string')throw Error('missing_issuer_key');
  const issuer=createPublicKey(pem.replace(/\\n/g,'\n'));
  if(issuer.asymmetricKeyType!=='ed25519')throw Error('issuer_must_be_ed25519');
  return (raw,holder)=>{
    const voucher=decodeIB1(raw);
    if(voucher.holderId!==holder||voucher.gatewayId!==gatewayId)throw Error('wrong_voucher_target');
    const ts=now();
    if(ts<voucher.issuedAtMs-60_000||ts>=voucher.expiresAtMs)throw Error('voucher_expired');
    if(!verify(null,Buffer.from(voucher.signedPayload,'utf8'),issuer,Buffer.from(voucher.signature,'base64url')))throw Error('invalid_voucher_signature');
    return Object.freeze(voucher);
  };
}

// Offline issuer: operator-signed research rights. A GB token has no meaning on a carrier network.
export function makeIB1({voucherId,holderId,gatewayId,quotaBytes,issuedAtMs,expiresAtMs},issuerPrivatePem){
  for(const [v,k] of [[voucherId,'voucher_id'],[holderId,'holder_id'],[gatewayId,'gateway_id']])assertId(v,k);
  if(!DENOMINATIONS.includes(quotaBytes))throw Error('research_package_must_be_1_5_or_10_gb');
  if(!Number.isSafeInteger(issuedAtMs)||!Number.isSafeInteger(expiresAtMs)||issuedAtMs<=0||expiresAtMs<=issuedAtMs||expiresAtMs-issuedAtMs>86_400_000)throw Error('invalid_window');
  const payload=[voucherId,holderId,gatewayId,quotaBytes,issuedAtMs,expiresAtMs].join('|');
  const key=issuerPrivatePem?.type==='private'?issuerPrivatePem:createPrivateKey(issuerPrivatePem);
  if(key.asymmetricKeyType!=='ed25519')throw Error('issuer_key_invalid');
  const signature=sign(null,Buffer.from(payload),key).toString('base64url');
  return 'IB1.'+Buffer.from(payload+'|'+signature,'utf8').toString('base64url');
}
