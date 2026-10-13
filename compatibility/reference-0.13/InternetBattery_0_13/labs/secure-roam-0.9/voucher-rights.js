'use strict';
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');

const FIELDS=['voucherId','holderId','targetGateway','quotaBytes','issuedAtMs','expiresAtMs','signature'];
const safeId=(s)=>typeof s==='string' && /^[A-Za-z0-9_-]{1,100}$/.test(s);
const digest=(s)=>crypto.createHash('sha256').update(s).digest('hex');
function voucherPayload(v) {
 return [v.voucherId,v.holderId,v.targetGateway,v.quotaBytes,v.issuedAtMs,v.expiresAtMs].join('|');
}
function decodeTicket(ticket) {
 if(typeof ticket!=='string')throw Error('invalid voucher input');
 let v;
 if(ticket.startsWith('IB1.')){
  if(ticket.length<80||ticket.length>255)throw Error('IB1 transport length');
  const encoded=ticket.slice(4);
  if(!/^[A-Za-z0-9_-]+$/.test(encoded))throw Error('IB1 characters');
  const data=Buffer.from(encoded,'base64url');
  if(data.toString('base64url')!==encoded)throw Error('noncanonical IB1 encoding');
  const fields=data.toString('utf8').split('|');
  if(fields.length!==7)throw Error('IB1 field count');
  if(!fields.slice(3,6).every(x=>/^(0|[1-9][0-9]*)$/.test(x)))throw Error('IB1 numeric fields');
  const [voucherId,holderId,targetGateway,quota,issued,expires,signature]=fields;
  v={voucherId,holderId,targetGateway,quotaBytes:Number(quota),issuedAtMs:Number(issued),expiresAtMs:Number(expires),signature};
 }else{
  if(ticket.length<80||ticket.length>1400||!/^[A-Za-z0-9_-]+$/.test(ticket))throw Error('invalid voucher transport');
  const data=Buffer.from(ticket,'base64url');
  if(data.length>950||data.toString('base64url')!==ticket)throw Error('noncanonical voucher encoding');
  v=JSON.parse(data.toString('utf8'));
  if(Object.keys(v).sort().join('|')!==FIELDS.slice().sort().join('|'))throw Error('unexpected voucher fields');
 }
 if(!safeId(v.voucherId)||!safeId(v.holderId)||!safeId(v.targetGateway))throw Error('invalid ids');
 if(!Number.isSafeInteger(v.quotaBytes)||v.quotaBytes<1||v.quotaBytes>50*1024*1024)throw Error('invalid quota');
 if(!Number.isSafeInteger(v.issuedAtMs)||!Number.isSafeInteger(v.expiresAtMs))throw Error('invalid validity');
 if(v.expiresAtMs-v.issuedAtMs>86_400_000||v.expiresAtMs<=v.issuedAtMs)throw Error('invalid duration');
 if(typeof v.signature!=='string'||!/^[-_A-Za-z0-9]{86}$/.test(v.signature))throw Error('invalid signature');
 if(Buffer.from(v.signature,'base64url').length!==64)throw Error('bad signature length');
 return v;
}

class VoucherRights {
 constructor({issuerPublicKeyPem,gatewayId,ledgerPath,ledgerMacKey,now=()=>Date.now()}){
  if(!safeId(gatewayId))throw Error('invalid gateway');
  if(!Buffer.isBuffer(ledgerMacKey)||ledgerMacKey.length<32)throw Error('invalid journal key');
  this.issuer=crypto.createPublicKey(issuerPublicKeyPem);
  if(this.issuer.asymmetricKeyType!=='ed25519')throw Error('Ed25519 required');
  this.gatewayId=gatewayId;this.journal=ledgerPath;this.key=Buffer.from(ledgerMacKey);this.now=now;
  this.entries={};
  this.restore();
 }
 mac(s){return crypto.createHmac('sha256',this.key).update(s).digest('hex');}
 persist(){
  const obj={version:1,entries:this.entries};
  const payload=JSON.stringify(obj);
  const signed=JSON.stringify({...obj,tag:this.mac(payload)});
  const tmp=this.journal+'.tmp';
  fs.mkdirSync(path.dirname(this.journal),{recursive:true,mode:0o700});
  const f=fs.openSync(tmp,'w',0o600);
  try{fs.writeFileSync(f,signed);fs.fsyncSync(f);}finally{fs.closeSync(f);}
  fs.renameSync(tmp,this.journal);
  const d=fs.openSync(path.dirname(this.journal),'r');
  try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
 }
 restore(){
  if(!fs.existsSync(this.journal)){this.entries={};this.persist();return;}
  const obj=JSON.parse(fs.readFileSync(this.journal,'utf8'));
  if(obj.version!==1 || !obj.entries || typeof obj.entries!=='object'||Array.isArray(obj.entries)||typeof obj.tag!=='string')throw Error('invalid ledger');
  const message=JSON.stringify({version:obj.version,entries:obj.entries});
  const expected=this.mac(message);
  if(obj.tag.length!==expected.length || !crypto.timingSafeEqual(Buffer.from(obj.tag),Buffer.from(expected)))throw Error('ledger authentication failed');
  for(const [id,item] of Object.entries(obj.entries)){
   if(!safeId(id)||!item||!Number.isSafeInteger(item.spent)||item.spent<0||typeof item.fingerprint!=='string'||!/^([0-9a-f]{64})$/.test(item.fingerprint))throw Error('invalid ledger entry');
  }
  this.entries=obj.entries;
 }
 verify(raw,holder){
  const v=decodeTicket(raw);
  if(v.holderId!==holder||v.targetGateway!==this.gatewayId)throw Error('wrong holder or gateway');
  const now=this.now();
  if(now<v.issuedAtMs-60_000||now>=v.expiresAtMs)throw Error('voucher expired or not yet valid');
  const payload=voucherPayload(v);
  if(!crypto.verify(null,Buffer.from(payload,'utf8'),this.issuer,Buffer.from(v.signature,'base64url')))throw Error('signature rejected');
  const fingerprint=digest(payload+'\n'+v.signature);
  const entry=this.entries[v.voucherId];
  if(entry && entry.fingerprint!==fingerprint)throw Error('voucher ID collision');
  return Object.freeze({voucherId:v.voucherId,quotaBytes:v.quotaBytes,expiresAtMs:v.expiresAtMs,fingerprint,holderId:holder});
 }
 spend(ticket,count){
  if(!Number.isSafeInteger(count)||count<0)return false;
  if(this.now()>=ticket.expiresAtMs)return false;
  const prev=this.entries[ticket.voucherId];
  if(prev && prev.fingerprint!==ticket.fingerprint)return false;
  const spent=prev?.spent||0;
  if(spent+count>ticket.quotaBytes)return false;
  this.entries[ticket.voucherId]={fingerprint:ticket.fingerprint,spent:spent+count};
  try{this.persist();return true;}catch(e){this.entries[ticket.voucherId]=prev;throw e;}
 }
 getSpent(voucherId){return this.entries[voucherId]?.spent||0;}
}
module.exports={VoucherRights,voucherPayload,decodeTicket};
