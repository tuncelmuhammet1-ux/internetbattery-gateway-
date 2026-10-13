import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {readConfig,signature,verifyHeaders,publicV4} from '../auth.mjs';

const config = readConfig({IB_MASTER_KEY:'a'.repeat(64),IB_DEVICE_ID:'phone-1',IB_SESSION_BYTE_CAP:'5242880'});

test('configuration fails closed without strong secret and device',()=>{
  assert.equal(readConfig({}),null);
  assert.equal(readConfig({IB_MASTER_KEY:'x',IB_DEVICE_ID:'phone-1'}),null);
  assert.equal(readConfig({IB_MASTER_KEY:'a'.repeat(64),IB_DEVICE_ID:'x'}),null);
  assert.equal(readConfig({IB_MASTER_KEY:'a'.repeat(64),IB_DEVICE_ID:'phone-1',IB_SESSION_BYTE_CAP:'1000000000'}),null);
  assert.ok(config);
});

test('signed header passes and tampering, expiry and bad length fail',()=>{
  const timestamp=String(Date.now()),nonce=randomBytes(16).toString('hex');
  const h={'x-ib-device':config.device,'x-ib-timestamp':timestamp,'x-ib-nonce':nonce,'x-ib-signature':signature(config,timestamp,nonce)};
  assert.equal(verifyHeaders(config,h).ok,true);
  assert.equal(verifyHeaders(config,{...h,'x-ib-device':'phone-2'}).ok,false);
  assert.equal(verifyHeaders(config,{...h,'x-ib-signature':'f'.repeat(64)}).ok,false);
  assert.equal(verifyHeaders(config,h,Date.now()+180000).ok,false);
  assert.equal(verifyHeaders(config,{...h,'x-ib-nonce':'abc'}).ok,false);
});

test('public IPv4 filter blocks loopback, metadata, private, link-local and reserved',()=>{
  const blocked=['127.0.0.1','10.4.0.1','172.16.0.5','192.168.1.2','169.254.169.254','100.64.0.1','0.0.0.0','192.0.0.9','192.0.2.3','198.51.100.8','203.0.113.10','224.0.0.1','255.255.255.255','999.4.5.6','::1'];
  blocked.forEach(ip=>assert.equal(publicV4(ip),false,ip));
  ['1.1.1.1','8.8.8.8','9.9.9.9','172.15.255.254'].forEach(ip=>assert.equal(publicV4(ip),true,ip));
});
