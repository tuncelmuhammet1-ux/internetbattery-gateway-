import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,generateKeyPairSync,sign,createHash} from 'node:crypto';
import {PostgresLedger} from '../ledger.mjs';
import {makeIB1,verifierFromPem,GB} from '../voucher.mjs';

const url=process.env.TEST_DATABASE_URL;
const TEST_OPTIONS={skip:!url?'TEST_DATABASE_URL unset; PostgreSQL integration is CI-only':false};

test('PostgreSQL survives new process/pool, idempotent grants and refuses double-spends',TEST_OPTIONS,async()=>{
  const pg=await import('pg');
  const Pool=pg.Pool||pg.default?.Pool;
  const pool=new Pool({connectionString:url,max:12,connectionTimeoutMillis:4000});
  const id='pilot_'+randomBytes(8).toString('hex'),holder='ib-'+randomBytes(6).toString('hex');
  const gb1=GB,gb5=5*GB,gb10=10*GB;
  const ledger=new PostgresLedger(pool);
  const now=Date.now();
  try{
    await ledger.init();
    const w0=await ledger.wallet(holder);assert.equal(w0.availableBytes,0);
    let w=await ledger.grant(holder,gb1,id+'_g1','lab_admin');assert.equal(w.availableBytes,gb1);assert.equal(w.idempotent,false);
    w=await ledger.grant(holder,gb1,id+'_g1','lab_admin');assert.equal(w.availableBytes,gb1);assert.equal(w.idempotent,true);
    await assert.rejects(ledger.grant(holder,gb5,id+'_g1','lab_admin'),/duplicate_grant_collision/);
    w=await ledger.grant(holder,gb5,id+'_g5','lab_admin');assert.equal(w.availableBytes,gb1+gb5);
    w=await ledger.grant(holder,gb10,id+'_g10','lab_admin');assert.equal(w.availableBytes,16*GB);
    const pair=generateKeyPairSync('ed25519'),priv=pair.privateKey.export({format:'pem',type:'pkcs8'}),pub=pair.publicKey.export({format:'pem',type:'spki'});
    const first=makeIB1({voucherId:id+'_v1',holderId:holder,gatewayId:'ib-gw1',quotaBytes:gb1,issuedAtMs:now,expiresAtMs:now+3600000},priv);
    const verified=verifierFromPem(pub,{gatewayId:'ib-gw1'})(first,holder);
    let balance=await ledger.balance(verified);assert.equal(balance.remaining,gb1);
    const sessionId=randomUUID();
    const r1=await ledger.spend(verified,8192,{sessionId,direction:'uplink'});assert.equal(r1.accepted,true);assert.equal(r1.remaining,gb1-8192);
    const r2=await ledger.spend(verified,3000,{sessionId,direction:'downlink'});assert.equal(r2.accepted,true);assert.equal(r2.remaining,gb1-11192);
    // Simulates restart by using a new independent PG pool, not the same in-memory ledger instance.
    const anotherPool=new Pool({connectionString:url,max:8,connectionTimeoutMillis:4000});
    try{
      const after=new PostgresLedger(anotherPool);
      balance=await after.balance(verified);assert.equal(balance.spent,11192);assert.equal(balance.remaining,gb1-11192);
      const wallet=await after.wallet(holder);assert.equal(wallet.spentBytes,11192);assert.equal(wallet.availableBytes,16*GB-11192);
      assert.equal(await after.claimNonce(holder,'ab'.repeat(16),Date.now()+120000),true);
      assert.equal(await ledger.claimNonce(holder,'ab'.repeat(16),Date.now()+120000),false);
      await assert.rejects(after.balance({...verified,fingerprint:'f'.repeat(64)}),/voucher_collision/);
    }finally{await anotherPool.end();}
    // Concurrent requests of 5000 bytes contend over one 50 KB signed voucher.
    const fields=[id+'_small',holder,'ib-gw1','50000',String(now),String(now+3600000)];
    const signedPayload=fields.join('|'),signature=sign(null,Buffer.from(signedPayload),pair.privateKey).toString('base64url');
    const raw='IB1.'+Buffer.from(signedPayload+'|'+signature).toString('base64url');
    const small=verifierFromPem(pub,{gatewayId:'ib-gw1'})(raw,holder);
    const calls=await Promise.all(Array.from({length:20},(_,i)=>ledger.spend(small,5000,{direction:i%2?'uplink':'downlink'})));
    assert.equal(calls.filter(x=>x.accepted).length,10);
    assert.equal(calls.filter(x=>!x.accepted).length,10);
    const finish=await ledger.balance(small);assert.equal(finish.remaining,0);assert.equal(finish.spent,50000);
    const events=await pool.query('SELECT COUNT(*) AS n,SUM(bytes) AS total FROM ib_spend_events_v1 WHERE voucher_id=$1',[small.voucherId]);
    assert.equal(Number(events.rows[0].n),10);assert.equal(Number(events.rows[0].total),50000);
  }finally{await pool.end();}
});
