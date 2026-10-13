import { createHmac, timingSafeEqual } from 'node:crypto';

const ID_RE = /^[A-Za-z0-9_-]{3,64}$/;
const HEX64 = /^[a-fA-F0-9]{64}$/;
const HEX_NONCE = /^[a-fA-F0-9]{32,128}$/;

export function readConfig(env = process.env) {
  const master = String(env.IB_MASTER_KEY || '').trim();
  const device = String(env.IB_DEVICE_ID || '').trim();
  if (!HEX64.test(master) || !ID_RE.test(device)) return null;
  const limit = Number(env.IB_SESSION_BYTE_CAP || '5242880');
  if (!Number.isSafeInteger(limit) || limit < 1024 || limit > 104857600) return null;
  return { key: Buffer.from(master, 'hex'), device, limit };
}

export function deviceSecret(config) {
  return createHmac('sha256', config.key).update('internetbattery-lab-device-v1\n' + config.device).digest();
}

export function signature(config, timestamp, nonce) {
  return createHmac('sha256', deviceSecret(config))
    .update('IB-LAB-WS1\n' + config.device + '\n' + timestamp + '\n' + nonce + '\n/ws')
    .digest('hex');
}

export function verifyHeaders(config, headers, now = Date.now()) {
  if (!config) return {ok:false, reason:'disabled'};
  const id = headers['x-ib-device'];
  const ts = headers['x-ib-timestamp'];
  const nonce = headers['x-ib-nonce'];
  const mac = headers['x-ib-signature'];
  if (Array.isArray(id) || Array.isArray(ts) || Array.isArray(nonce) || Array.isArray(mac)) return {ok:false, reason:'invalid'};
  if (id !== config.device || typeof ts !== 'string' || !/^\d{13}$/.test(ts) ||
      typeof nonce !== 'string' || !HEX_NONCE.test(nonce) ||
      typeof mac !== 'string' || !HEX64.test(mac)) return {ok:false, reason:'invalid'};
  const t = Number(ts);
  if (!Number.isSafeInteger(t) || Math.abs(now - t) > 2 * 60 * 1000) return {ok:false, reason:'expired'};
  const expected = Buffer.from(signature(config, ts, nonce), 'hex');
  const provided = Buffer.from(mac, 'hex');
  if (!timingSafeEqual(provided, expected)) return {ok:false, reason:'signature'};
  return {ok:true, nonce:nonce.toLowerCase(), timestamp:t};
}

// Block loopback, private, link-local, metadata and reserved IP space.
export function publicV4(ip) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!match) return false;
  const a = match.slice(1).map(Number);
  if (a.some(x => x > 255)) return false;
  const [x,y,z] = a;
  if (x === 0 || x === 10 || x === 127 || x >= 224) return false;
  if (x === 100 && y >= 64 && y <= 127) return false;
  if (x === 169 && y === 254) return false;
  if (x === 172 && y >= 16 && y <= 31) return false;
  if (x === 192 && (y === 168 || (y === 0 && z === 0) || (y === 0 && z === 2) || (y === 88 && z === 99))) return false;
  if (x === 198 && (y === 18 || y === 19 || (y === 51 && z === 100))) return false;
  if (x === 203 && y === 0 && z === 113) return false;
  if (x === 255) return false;
  return true;
}
