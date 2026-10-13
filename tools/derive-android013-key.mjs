#!/usr/bin/env node
// Run ONLY on the operator's trusted terminal, with IB_MASTER_KEY in the env.
// Do not commit the master key, derived key or an .env file.
import {createHmac} from 'node:crypto';
import {readConfig} from '../auth.mjs';
const cfg=readConfig(process.env);
if(!cfg){console.error('IB_MASTER_KEY (64 hex) and IB_DEVICE_ID are required as environment variables.');process.exitCode=1;}
else {
  const key=createHmac('sha256',cfg.key).update('IB09-device:'+cfg.device).digest('hex');
  // The output is SECRET device authentication material. Handle securely.
  console.log(`DEVICE_ID=${cfg.device}`);
  console.log(`ANDROID_013_DEVICE_KEY=${key}`);
}
