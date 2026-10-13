# INTERNET BATTERY — Remote Gateway (research/lab)

**Türkçe durum:** Render üzerindeki 0.14.1 laboratuvar ağ geçidi, Android 0.13 uygulamasının eski WSS `/tunnel` bağlantı protokolünü artık destekler. Bu destek yalnızca kimlik doğrulama, DNS ve kotalı veri aktarımı içindir; **IB1 imzalı kredi harcaması henüz etkin değildir**. İnterneti fiziksel bağlantı olmadan depoladığımız iddia edilmez. Sunucu anahtarı yalnızca Render gizli ortam değişkenlerinde saklanmalıdır.

This is a non-production Internet Battery research gateway. **0.14.1-lab supports Android 0.13's transport handshake and binary relay, but explicitly rejects IB1 vouchers until a durable spent-credit ledger is available.** Do not enter financial credentials through this service.

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

## Android 0.13 compatibility — 0.14.1 lab update

The hosted server can now also accept the **original Android 0.13 transport wire format** at:

`wss://internetbattery-gateway.onrender.com/tunnel`

Set `IB_ANDROID013_COMPAT=1` in the Render environment to activate `/tunnel` after the adapter has passed tests; without this flag the endpoint returns HTTP 404. This `/tunnel` endpoint accepts the Android client's `X-IB-ID`, `X-IB-TS`, `X-IB-Nonce`, and `X-IB-MAC` handshake as defined by `WssCredentials.kt`; responds to `{ "op": "dns", "host": "example.com" }` with the Android-expected `op/dns/host/address/ipFamily` response; and supports `{ "op": "connect", "host": "...", "port": 443 }`, masked binary WebSocket frames, and restricted UDP/53. The original new `/ws` WS1 endpoint remains available for its separate lab tests.

For the legacy Android device key, derive **only the device key**, not the master secret, using:

`deviceKey = HMAC_SHA256(IB_MASTER_KEY_BYTES, UTF8("IB09-device:" + IB_DEVICE_ID))`

Only the 64-hex derived key should be entered into the Android app along with the exact device ID. The server master key must remain private in Render. To generate the device key in a trusted terminal where the Render master key is already configured as a protected environment variable, run `node tools/derive-android013-key.mjs`. Do not paste secrets into issues or logs.

**Deliberate safety restrictions:** The adapter is experimental and **does not accept** the `X-IB-Voucher` header. It rejects these requests with HTTP 403 rather than granting false credit. This means the signed IB1 credits of Android 0.13 cannot be spent on this Render free service; a durable, tamper-resistant spent-amount ledger and issuer key provisioning are still prerequisites. The non-voucher lab transport uses a **5 MiB process-lifetime cap** by default; it is not commercial metering and resets on server restart. Each session is capped at 10 minutes, 4 concurrent Android sockets are allowed, and UDP support is DNS/53 only. HTTPS certificate validation occurs on the Android client, not at the relay.

In a lab phone test, first use Android 0.13 with an **empty voucher field**, WSS `/tunnel`, the provisioned device ID and derived device key. Run the preflight before enabling VPN. Wi-Fi must still be online; when mobile data is disabled outside the home, a participating physical network remains essential. Do not use this research relay for banking or sensitive accounts.

### Verification

- `npm test` includes legacy WS1 regressions, Android 0.13 HMAC header parity, replay protection, explicit voucher denial, DNS response structure, SSRF protections, and byte-perfect raw WebSocket binary forwarding against a local synthetic TCP upstream.
- A deterministic 0.13 HMAC test vector has been cross-checked against a separate Kotlin JVM implementation (`IB09-device:` derivation + signed header fields).
- A successful localhost fake upstream or CI test is not evidence of live phone TUN function, IPv6, QUIC, physical network coverage, or signed-credit redemption.
