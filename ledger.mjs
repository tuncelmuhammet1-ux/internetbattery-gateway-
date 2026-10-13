// Durable, transactional IB1 spent-credit accounting. No schema or data is written to the Render web-service filesystem.
// Free Render Postgres expires after 30 days: this is a research trial, not permanent production storage.
import {randomUUID} from 'node:crypto';

const MAX=10_000_000_000;
const DAILY_RELAY_CAP=100_000_000; // 100 MB/day aggregate: cost guard for free lab server
function validVoucher(v){
  if(!v||typeof v.voucherId!=='string'||typeof v.holderId!=='string'||typeof v.gatewayId!=='string'||
    typeof v.fingerprint!=='string'||!/^[0-9a-f]{64}$/.test(v.fingerprint)||
    !Number.isSafeInteger(v.quotaBytes)||v.quotaBytes<1||v.quotaBytes>MAX||
    !Number.isSafeInteger(v.expiresAtMs))throw Error('invalid_signed_voucher');
}
function convert(row,v){
  if(!row||row.fingerprint!==v.fingerprint||row.holder_id!==v.holderId||row.gateway_id!==v.gatewayId||Number(row.quota_bytes)!==v.quotaBytes||Number(row.expires_at_ms)!==v.expiresAtMs)throw Error('voucher_collision');
  const spent=Number(row.spent_bytes),total=Number(row.quota_bytes);
  if(!Number.isSafeInteger(spent)||spent<0||spent>total)throw Error('invalid_ledger_spent');
  return {voucherId:v.voucherId,quotaBytes:total,spent,remaining:total-spent};
}

export class PostgresLedger {
  constructor(pool,{now=()=>Date.now()}={}){this.pool=pool;this.now=now;}
  async init(){
    const client=await this.pool.connect();
    try{
      await client.query(`CREATE TABLE IF NOT EXISTS ib_vouchers_v1 (
        voucher_id VARCHAR(100) PRIMARY KEY, holder_id VARCHAR(100) NOT NULL, gateway_id VARCHAR(100) NOT NULL,
        fingerprint CHAR(64) NOT NULL, quota_bytes BIGINT NOT NULL CHECK (quota_bytes>0 AND quota_bytes<=10000000000),
        spent_bytes BIGINT NOT NULL DEFAULT 0 CHECK (spent_bytes>=0 AND spent_bytes<=quota_bytes),
        expires_at_ms BIGINT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
      await client.query(`CREATE TABLE IF NOT EXISTS ib_spend_events_v1 (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        voucher_id VARCHAR(100) NOT NULL REFERENCES ib_vouchers_v1(voucher_id),
        session_id UUID NOT NULL, bytes BIGINT NOT NULL CHECK(bytes>0 AND bytes<=65536),
        direction VARCHAR(16) NOT NULL CHECK(direction IN ('uplink','downlink','dns_uplink','dns_downlink')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
      await client.query(`CREATE TABLE IF NOT EXISTS ib_wallets_v1 (
        holder_id VARCHAR(100) PRIMARY KEY,
        credited_bytes BIGINT NOT NULL DEFAULT 0 CHECK(credited_bytes>=0 AND credited_bytes<=50000000000),
        spent_bytes BIGINT NOT NULL DEFAULT 0 CHECK(spent_bytes>=0 AND spent_bytes<=credited_bytes),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
      await client.query(`CREATE TABLE IF NOT EXISTS ib_wallet_grants_v1 (
        grant_id VARCHAR(100) PRIMARY KEY, holder_id VARCHAR(100) NOT NULL REFERENCES ib_wallets_v1(holder_id),
        credit_bytes BIGINT NOT NULL CHECK(credit_bytes>0 AND credit_bytes<=10000000000),
        grant_source VARCHAR(32) NOT NULL, granted_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
      await client.query(`CREATE TABLE IF NOT EXISTS ib_wallet_nonces_v1 (
        device_id VARCHAR(100) NOT NULL, nonce VARCHAR(64) NOT NULL, expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY(device_id,nonce)
      )`);
      await client.query(`CREATE TABLE IF NOT EXISTS ib_daily_relay_v1 (
        day_utc DATE PRIMARY KEY, used_bytes BIGINT NOT NULL DEFAULT 0 CHECK(used_bytes>=0 AND used_bytes<=100000000)
      )`);
      await client.query('SELECT 1');
    }finally{client.release();}
  }
  async withTx(fn){
    const client=await this.pool.connect();
    try{
      await client.query('BEGIN');
      const r=await fn(client);
      await client.query('COMMIT');return r;
    }catch(e){try{await client.query('ROLLBACK');}catch{}throw e;}
    finally{client.release();}
  }
  async recordOrRead(client,v){
    validVoucher(v);
    if(this.now()>=v.expiresAtMs)throw Error('voucher_expired');
    await client.query(`INSERT INTO ib_vouchers_v1 (voucher_id,holder_id,gateway_id,fingerprint,quota_bytes,expires_at_ms)
      VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (voucher_id) DO NOTHING`,
    [v.voucherId,v.holderId,v.gatewayId,v.fingerprint,v.quotaBytes,v.expiresAtMs]);
    const r=await client.query('SELECT voucher_id,holder_id,gateway_id,fingerprint,quota_bytes,spent_bytes,expires_at_ms FROM ib_vouchers_v1 WHERE voucher_id=$1 FOR UPDATE',[v.voucherId]);
    return convert(r.rows[0],v);
  }
  static asWallet(row){
    if(!row)throw Error('wallet_not_funded');
    const creditedBytes=Number(row.credited_bytes),spentBytes=Number(row.spent_bytes);
    if(!Number.isSafeInteger(creditedBytes)||!Number.isSafeInteger(spentBytes)||spentBytes<0||spentBytes>creditedBytes)throw Error('invalid_wallet_state');
    return {holderId:row.holder_id,creditedBytes,spentBytes,availableBytes:creditedBytes-spentBytes};
  }
  async lockWallet(c,holderId){
    const r=await c.query('SELECT * FROM ib_wallets_v1 WHERE holder_id=$1 FOR UPDATE',[holderId]);
    return PostgresLedger.asWallet(r.rows[0]);
  }
  async wallet(holderId){
    if(typeof holderId!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(holderId))throw Error('invalid_holder');
    const r=await this.pool.query('SELECT * FROM ib_wallets_v1 WHERE holder_id=$1',[holderId]);
    if(!r.rowCount)return {holderId,creditedBytes:0,spentBytes:0,availableBytes:0};
    return PostgresLedger.asWallet(r.rows[0]);
  }
  async grant(holderId,creditBytes,grantId,source='lab_admin'){
    if(typeof holderId!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(holderId) ||
       typeof grantId!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(grantId)||
       ![1_000_000_000,5_000_000_000,10_000_000_000].includes(creditBytes)||
       !['lab_admin','signed_receipt'].includes(source))throw Error('invalid_grant');
    return this.withTx(async c=>{
      await c.query(`INSERT INTO ib_wallets_v1(holder_id) VALUES($1) ON CONFLICT DO NOTHING`,[holderId]);
      const existing=await c.query('SELECT * FROM ib_wallet_grants_v1 WHERE grant_id=$1 FOR UPDATE',[grantId]);
      if(existing.rowCount){
        const row=existing.rows[0];
        if(row.holder_id!==holderId||Number(row.credit_bytes)!==creditBytes||row.grant_source!==source)throw Error('duplicate_grant_collision');
        return {...await this.lockWallet(c,holderId),idempotent:true};
      }
      await c.query(`INSERT INTO ib_wallet_grants_v1(grant_id,holder_id,credit_bytes,grant_source) VALUES($1,$2,$3,$4)`,[grantId,holderId,creditBytes,source]);
      const row=await c.query(`UPDATE ib_wallets_v1 SET credited_bytes=credited_bytes+$2,updated_at=now()
        WHERE holder_id=$1 AND credited_bytes+$2<=50000000000 RETURNING *`,[holderId,creditBytes]);
      if(row.rowCount!==1)throw Error('wallet_credit_cap');
      return {...PostgresLedger.asWallet(row.rows[0]),idempotent:false};
    });
  }
  async claimNonce(holder,nonce,expiryMs){
    if(typeof holder!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(holder)||
      typeof nonce!=='string'||!/^[a-f0-9]{24,64}$/.test(nonce)||!Number.isSafeInteger(expiryMs))throw Error('invalid_nonce');
    const r=await this.pool.query(`INSERT INTO ib_wallet_nonces_v1(device_id,nonce,expires_at_ms)
      VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING nonce`,[holder,nonce,expiryMs]);
    return r.rowCount===1;
  }
  async balance(v){
    return this.withTx(async c=>{
      const wallet=await this.lockWallet(c,v.holderId);
      const voucher=await this.recordOrRead(c,v);
      return {...voucher,remaining:Math.min(voucher.remaining,wallet.availableBytes),walletAvailable:wallet.availableBytes};
    });
  }
  async spend(v,bytes,{direction='uplink',sessionId=randomUUID()}={}){
    if(!Number.isSafeInteger(bytes)||bytes<1||bytes>65536)throw Error('invalid_spend_amount');
    if(!['uplink','downlink','dns_uplink','dns_downlink'].includes(direction))throw Error('invalid_direction');
    if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId))throw Error('invalid_session_id');
    return this.withTx(async c=>{
      const wallet=await this.lockWallet(c,v.holderId);
      const previous=await this.recordOrRead(c,v); // locked row ensures no concurrent overdraw
      if(bytes>previous.remaining||bytes>wallet.availableBytes)return {...previous,remaining:Math.min(previous.remaining,wallet.availableBytes),accepted:false};
      const cap=await c.query(`INSERT INTO ib_daily_relay_v1(day_utc,used_bytes) VALUES((now() AT TIME ZONE 'UTC')::date,$1)
        ON CONFLICT(day_utc) DO UPDATE SET used_bytes=ib_daily_relay_v1.used_bytes+EXCLUDED.used_bytes
        WHERE ib_daily_relay_v1.used_bytes+EXCLUDED.used_bytes <= 100000000 RETURNING used_bytes`,[bytes]);
      if(cap.rowCount!==1)return {...previous,remaining:Math.min(previous.remaining,wallet.availableBytes),accepted:false,dayLimitReached:true};
      const result=await c.query(`UPDATE ib_vouchers_v1 SET spent_bytes=spent_bytes+$2,updated_at=now()
        WHERE voucher_id=$1 AND fingerprint=$3 AND spent_bytes+$2<=quota_bytes
        RETURNING voucher_id,holder_id,gateway_id,fingerprint,quota_bytes,spent_bytes,expires_at_ms`,[v.voucherId,bytes,v.fingerprint]);
      if(result.rowCount!==1)throw Error('ledger_conflict');
      const walletUpdate=await c.query(`UPDATE ib_wallets_v1 SET spent_bytes=spent_bytes+$2,updated_at=now()
        WHERE holder_id=$1 AND spent_bytes+$2<=credited_bytes RETURNING *`,[v.holderId,bytes]);
      if(walletUpdate.rowCount!==1)throw Error('wallet_conflict');
      await c.query(`INSERT INTO ib_spend_events_v1(voucher_id,session_id,bytes,direction) VALUES ($1,$2,$3,$4)`,[v.voucherId,sessionId,bytes,direction]);
      const voucherBalance=convert(result.rows[0],v),afterWallet=PostgresLedger.asWallet(walletUpdate.rows[0]);
      return {...voucherBalance,remaining:Math.min(voucherBalance.remaining,afterWallet.availableBytes),walletAvailable:afterWallet.availableBytes,accepted:true};
    });
  }
  async close(){await this.pool.end();}
}

export async function connectPostgresLedger(url,opts={}){
  if(typeof url!=='string'||!/^postgres(ql)?:\/\//.test(url))throw Error('DATABASE_URL_not_configured');
  // Do not print URLs or credentials to logs, even on failed connections.
  const pg=await import('pg');
  const Pool=pg.Pool||pg.default?.Pool;
  const pool=new Pool({connectionString:url,max:5,connectionTimeoutMillis:7000,idleTimeoutMillis:20000,
    ssl:opts.ssl === true?{rejectUnauthorized:true}:undefined,application_name:'internetbattery-ledger-lab'});
  const ledger=new PostgresLedger(pool);
  try{await ledger.init();return ledger;}catch(e){await pool.end();throw Error('database_initialization_failed:'+(e.code||'unknown'));}
}
