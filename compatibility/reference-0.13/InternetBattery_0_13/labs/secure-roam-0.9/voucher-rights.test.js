'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os'),path=require('node:path');
const {VoucherRights,voucherPayload,decodeTicket}=require('./voucher-rights');
const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519');
const {publicKey:wrongIssuer}=crypto.generateKeyPairSync('ed25519');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ib13-ticket-'));
const journal=path.join(dir,'spent.json');
const key=crypto.randomBytes(32);
const now=()=>Date.now();
function makeTicket(opts={}){
 const base={voucherId:'voucher-A',holderId:'device-A',targetGateway:'gateway-b',quotaBytes:8192,issuedAtMs:now()-1000,expiresAtMs:now()+300_000,...opts};
 const payload=voucherPayload(base);
 const signature=crypto.sign(null,Buffer.from(payload),privateKey).toString('base64url');
 return Buffer.from(JSON.stringify({...base,signature})).toString('base64url');
}
const create=()=>new VoucherRights({issuerPublicKeyPem:publicKey.export({type:'spki',format:'pem'}),gatewayId:'gateway-b',ledgerPath:journal,ledgerMacKey:key});
let count=0;
function ok(name,fn){
 try{fn();console.log('PASS '+name);count++;}
 catch(e){console.error('FAIL '+name,e);throw e;}
}
const rights=create();
function makeIB1(opts={}){
 const b={voucherId:'ticket-ib1',holderId:'device-A',targetGateway:'gateway-b',quotaBytes:8000,issuedAtMs:now()-1000,expiresAtMs:now()+300000,...opts};
 const payload=voucherPayload(b);
 const sig=crypto.sign(null,Buffer.from(payload),privateKey).toString('base64url');
 return 'IB1.'+Buffer.from(payload+'|'+sig).toString('base64url');
}
const original=makeTicket();
let decoded,authorized;
ok('signed Ed25519 valid',()=>{decoded=decodeTicket(original);authorized=rights.verify(original,'device-A');assert.equal(decoded.voucherId,'voucher-A');});
ok('Kotlin-compatible IB1 accepted',()=>{
 const raw=makeIB1();
 const v=rights.verify(raw,'device-A');
 assert.equal(v.voucherId,'ticket-ib1');assert.equal(v.quotaBytes,8000);
 assert.ok(raw.length<=255);
});
ok('IB1 forged quota denied',()=>{
 const raw=makeIB1();const str=Buffer.from(raw.slice(4),'base64url').toString('utf8');
 const changed=str.replace('|8000|','|9000|');
 assert.throws(()=>rights.verify('IB1.'+Buffer.from(changed).toString('base64url'),'device-A'),/signature/);
});
ok('wrong holder denied',()=>assert.throws(()=>rights.verify(original,'device-B'),/holder/));
ok('different gateway denied',()=>assert.throws(()=>rights.verify(makeTicket({targetGateway:'gateway-c'}),'device-A'),/gateway/));
ok('expired rejected',()=>assert.throws(()=>rights.verify(makeTicket({expiresAtMs:now()-1}),'device-A'),/expired/));
ok('not yet valid rejected',()=>assert.throws(()=>rights.verify(makeTicket({issuedAtMs:now()+150_000,expiresAtMs:now()+200_000}),'device-A'),/not yet valid/));
ok('tampering blocked',()=>{let obj=JSON.parse(Buffer.from(original,'base64url'));obj.quotaBytes=50_000;assert.throws(()=>rights.verify(Buffer.from(JSON.stringify(obj)).toString('base64url'),'device-A'),/signature/);});
ok('wrong issuer rejected',()=>{const alt=new VoucherRights({issuerPublicKeyPem:wrongIssuer.export({type:'spki',format:'pem'}),gatewayId:'gateway-b',ledgerPath:journal,ledgerMacKey:key});assert.throws(()=>alt.verify(original,'device-A'),/signature/);});
ok('charge counts actual bytes',()=>{assert.equal(rights.spend(authorized,4096),true);assert.equal(rights.spend(authorized,4096),true);assert.equal(rights.getSpent('voucher-A'),8192);});
ok('over quota blocked',()=>assert.equal(rights.spend(authorized,1),false));
ok('no negative or nonint counts',()=>{assert.equal(rights.spend(authorized,-4),false);assert.equal(rights.spend(authorized,1.2),false)});
ok('replay consumption survives restart',()=>{const restored=create();const token=restored.verify(original,'device-A');assert.equal(restored.getSpent('voucher-A'),8192);assert.equal(restored.spend(token,1),false)});
ok('clashing ID with changed signed quota rejected',()=>assert.throws(()=>create().verify(makeTicket({quotaBytes:10000}),'device-A'),/collision/));
ok('concurrent debit never over quota',()=>{
 const id='voucher-B',tok=makeTicket({voucherId:id,quotaBytes:10});
 const t=rights.verify(tok,'device-A');
 const outcomes=Array.from({length:40},()=>rights.spend(t,1));
 assert.equal(outcomes.filter(Boolean).length,10);
 assert.equal(rights.getSpent(id),10);
});
ok('journal tamper fails closed',()=>{
 const j=JSON.parse(fs.readFileSync(journal,'utf8'));
 j.entries['voucher-A'].spent=0;
 fs.writeFileSync(journal,JSON.stringify(j));
 assert.throws(()=>create(),/authentication failed/);
});
ok('fresh ticket upper bounds enforced',()=>assert.throws(()=>decodeTicket(makeTicket({quotaBytes:999_999_999})),/quota/));
fs.rmSync(dir,{recursive:true,force:true});
console.log('IB13 RIGHTS TESTS: '+count+' PASS');
