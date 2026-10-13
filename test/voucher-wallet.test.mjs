import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {readConfig} from '../auth.mjs';
import {makeIB1,decodeIB1,verifierFromPem,GB} from '../voucher.mjs';
import {walletDeviceKey,walletMac,verifyWalletRequest,makeWalletApi} from '../wallet-api.mjs';
import {makeServer} from '../server.mjs';

const keyPair=generateKeyPairSync('ed25519');
const priv=keyPair.privateKey.export({format:'pem',type:'pkcs8'}),pub=keyPair.publicKey.export({format:'pem',type:'spki'});
const now=Date.now();
const params={voucherId:'v-'+randomBytes(6).toString('hex'),holderId:'ib-device-13',gatewayId:'ib-gw1',quotaBytes:GB,issuedAtMs:now,expiresAtMs:now+3_600_000};

test('offline issuance creates canonical Android-compatible 1,5,10 GB IB1 tokens',()=>{
  const verify=verifierFromPem(pub,{gatewayId:'ib-gw1',now:()=>now+100});
  for(const factor of [1,5,10]){
    const raw=makeIB1({...params,quotaBytes:factor*GB},priv);
    assert.ok(raw.length<=255,'must meet Android 0.13 255 character limit');
    const v=verify(raw,params.holderId);
    assert.equal(v.quotaBytes,factor*GB);
    assert.equal(decodeIB1(raw).voucherId,params.voucherId);
    assert.throws(()=>verify(raw,'wrong-user'),/wrong_voucher_target/);
    assert.throws(()=>verifierFromPem(pub,{gatewayId:'wrong-gw',now:()=>now+100})(raw,params.holderId),/wrong_voucher_target/);
    const changed=raw.slice(0,-2)+(raw.at(-2)==='X'?'Y':'X')+raw.at(-1);
    assert.throws(()=>verify(changed,params.holderId));
  }
});

test('expired and forged vouchers cannot become credit',()=>{
  const raw=makeIB1(params,priv),other=generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'});
  assert.throws(()=>verifierFromPem(other,{gatewayId:'ib-gw1',now:()=>now+100})(raw,params.holderId),/invalid_voucher_signature/);
  assert.throws(()=>verifierFromPem(pub,{gatewayId:'ib-gw1',now:()=>params.expiresAtMs+1})(raw,params.holderId),/voucher_expired/);
  assert.throws(()=>makeIB1({...params,quotaBytes:12*GB},priv),/research_package/);
});

test('wallet HTTPS request HMAC binds method, endpoint and body, does not reveal device key',()=>{
  const cfg=readConfig({IB_MASTER_KEY:'ab'.repeat(32),IB_DEVICE_ID:params.holderId});
  const ts=String(Date.now()),nonce=randomBytes(16).toString('hex'),body=JSON.stringify({packageGb:5});
  const signature=walletMac(cfg,params.holderId,ts,nonce,'POST','/v1/wallet/issue',body);
  const headers={'x-ib-id':params.holderId,'x-ib-ts':ts,'x-ib-nonce':nonce,'x-ib-mac':signature};
  assert.equal(walletDeviceKey(cfg).length,32);
  assert.equal(verifyWalletRequest(cfg,headers,'POST','/v1/wallet/issue',body),true);
  assert.equal(verifyWalletRequest(cfg,headers,'POST','/v1/wallet/balance',body),false);
  assert.equal(verifyWalletRequest(cfg,headers,'POST','/v1/wallet/issue',JSON.stringify({packageGb:10})),false);
  assert.equal(verifyWalletRequest(cfg,{...headers,'x-ib-mac':'0'.repeat(64)},'POST','/v1/wallet/issue',body),false);
});

test('authenticated wallet portal can issue signed IB1 from credited mock wallet and rejects replay',async()=>{
 const env={IB_MASTER_KEY:'ab'.repeat(32),IB_DEVICE_ID:params.holderId,IB_CREDIT_DB_ENABLED:'1',IB_ISSUER_PUBLIC_KEY_PEM:pub,IB_ISSUER_PRIVATE_KEY_PEM:priv,IB_VOUCHER_GATEWAY_ID:'ib-gw1',IB_WALLET_HTTP_ENABLED:'1',IB_ANDROID013_COMPAT:'1'};
 let nonceUsed=new Set();
 const ledger={
   claimNonce:async(id,nonce)=>{if(nonceUsed.has(nonce))return false;nonceUsed.add(nonce);return true;},
   wallet:async id=>({holderId:id,creditedBytes:16*GB,spentBytes:GB,availableBytes:15*GB}),
   balance:async v=>({voucherId:v.voucherId,quotaBytes:v.quotaBytes,spent:0,remaining:v.quotaBytes}),
   spend:async()=>({accepted:true,remaining:1}),
 };
 const svr=makeServer(env,{ledger});
 await new Promise(resolve=>svr.listen(0,'127.0.0.1',resolve));
 const url='http://127.0.0.1:'+svr.address().port;
 try{
   const page=await fetch(url+'/wallet');assert.equal(page.status,200);assert.match(await page.text(),/Deneysel kullanım hakkı/);
   const ready=await fetch(url+'/readyz');const r=await ready.json();assert.equal(r.creditLedgerReady,true);assert.equal(r.walletPortalReady,true);
   const cfg=readConfig(env);const body=JSON.stringify({packageGb:5}),ts=String(Date.now()),nonce=randomBytes(16).toString('hex');
   const sig=walletMac(cfg,params.holderId,ts,nonce,'POST','/v1/wallet/issue',body);
   const headers={'x-ib-id':params.holderId,'x-ib-ts':ts,'x-ib-nonce':nonce,'x-ib-mac':sig,'Content-Type':'application/json'};
   const response=await fetch(url+'/v1/wallet/issue',{method:'POST',headers,body});assert.equal(response.status,200);
   const v=await response.json();assert.equal(verifierFromPem(pub,{gatewayId:'ib-gw1'})(v.voucher,params.holderId).quotaBytes,5*GB);
   const replay=await fetch(url+'/v1/wallet/issue',{method:'POST',headers,body});assert.equal(replay.status,409);
   const fake=await fetch(url+'/v1/wallet/issue',{method:'POST',headers:{...headers,'x-ib-mac':'0'.repeat(64)},body});assert.equal(fake.status,401);
 }finally{await new Promise(done=>svr.close(done));}
});
