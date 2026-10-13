# INTERNET BATTERY — Remote Gateway (research/lab)

**Türkçe durum:** Android 0.13 laboratuvarındaki gerçek trafik/kota deneyi korunmuştur. Bu depo, kalıcı Render sunucusuna geçiş için hazırlanmış **yeni 0.14 laboratuvar WSS aktarım denemesidir**. Mevcut Android 0.13 + IB1 protokolüyle henüz uyumlu değildir ve interneti bağlantı olmadan sakladığını iddia etmez. Anahtarların yalnızca Render ortam değişkenlerinde tutulması gerekir.

This repository is an independent, non-production Render gateway experiment for the Internet Battery project. **0.14.0-lab is a new, explicitly versioned WSS laboratory wire protocol and is NOT compatible with the previous Android 0.13 IB1 voucher client without an adapter.** Do not enter financial credentials through this service.

## What it does

- Node 22 built-ins only. `npm test` runs without network/dependency installation.
- `/healthz` (process alive), `/readyz` (secrets configured; NOT an Android end-to-end readiness test).
- `GET /ws`: authenticated WebSocket handshake, replay-resistant nonce, protected TCP connections to public IPv4 addresses on ports 80/443, limited DNS, limited forwarding quota and max 4 TCP streams per socket.
- Prevents direct access to loopback, metadata IP, private and link-local ranges. No master key or per-device key in the repository.

## Render deployment

Repository: `tuncelmuhammet1-ux/internetbattery-gateway-` (note trailing hyphen). Use **Frankfurt, Node 22+, free** for an experimental service, start `npm start`, health check `/healthz`. See `render.yaml`.

Set these Render environment variables in the dashboard, **not GitHub**:

| Variable | Meaning |
|---|---|
| `IB_MASTER_KEY` | Private 64-character hex key (generate using `openssl rand -hex 32`) |
| `IB_DEVICE_ID` | Allowed device ID (3–64 letters/numbers/dash/underscore) |
| `IB_SESSION_BYTE_CAP` | Experimental per-WebSocket byte cap; default 5 MiB |

`IB_MASTER_KEY` is used only to derive a device-specific HMAC key. Never place it in an APK, logs, issue, repository, or chat. The per-device key can be derived locally using an audited provisioning tool (not yet packaged) and given to the phone in a secure channel. Until that provisioning is implemented, do **not** connect an Android VPN.

## Lab WS1 handshake (new test protocol)

Send request to `wss://<render-host>/ws` with headers:

- `X-IB-Device`: configured device ID
- `X-IB-Timestamp`: current UTC epoch milliseconds (13 digits)
- `X-IB-Nonce`: cryptographic random hex, 32–128 characters, never reused
- `X-IB-Signature`: lowercase hex HMAC-SHA256 over `IB-LAB-WS1\n${device}\n${timestamp}\n${nonce}\n/ws`, using the per-device key derived by `HMAC-SHA256(masterKey, 'internetbattery-lab-device-v1\n' + device)`

Single-frame masked WebSocket JSON text commands:

- `{"t":"status"}` -> `{"t":"status","used":0,"limit":...,"remaining":...}`
- `{"t":"dns","id":"d1","host":"example.com"}` -> `{"t":"dns","id":"d1","addrs":[...]}`
- `{"t":"open","id":"s1","host":"example.com","port":443}` -> `{"t":"open","id":"s1"}`
- `{"t":"data","id":"s1","b64":"..."}` -> outgoing TCP bytes; incoming TCP is sent back as `{"t":"data","id":"s1","b64":"..."}`
- `{"t":"close","id":"s1"}` -> close TCP stream.

TLS certificate validation and hostname checks must take place in the **client application**; the gateway is byte-forwarding only. Generic QUIC/UDP, IPv6 and multi-app Android TUN are not implemented.

## Boundaries and next integration gate

Previous Internet Battery 0.13 Android + IB1 research demonstrated laboratory Ed25519 voucher issuance/redeeming and metered HTTPS traffic. This repository does NOT yet contain that exact 0.13 IB1 server source. Because the exact original code is not available locally, the lab WS1 endpoint **must not be represented as a compatible replacement**. Import and audit the `InternetBattery_0_13_Source_And_Verification.zip` gateway source and align the Android wire protocol, signed voucher verification and persistent quota journal before a real phone trial.

Internet use cannot be banked as live packet traffic independent of physical connectivity. The planned service model is a portable entitlement, redeemable over participating Wi-Fi/mesh/other authorized Internet networks. Mobile data off and outside home Wi-Fi still requires a participant access network.

## Local development

```bash
npm test
IB_MASTER_KEY="$(openssl rand -hex 32)" IB_DEVICE_ID="phone-lab" node server.mjs
curl http://127.0.0.1:3000/healthz
curl http://127.0.0.1:3000/readyz
```

This is a research service, not a production VPN. Quotas are per socket and reset on reconnection; no durable voucher accounting or billing support is claimed. Render free services can sleep and use ephemeral storage.
