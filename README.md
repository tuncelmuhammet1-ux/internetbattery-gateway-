# INTERNET BATTERY — 0.15 PostgreSQL wallet pilot

> **Research network entitlement, not stored cellular internet.** A prepaid research byte right still requires an authorized Wi-Fi, Ethernet, mesh or other physical data connection, plus an upstream gateway. The Android VPN and real phone have **not** passed a remote field acceptance test. This service is not an operator, tariff replacement or production VPN.

## Proven / unproven

- Node `0.15.0-lab` retains `/ws` and Android 0.13 `/tunnel`, including HMAC handshake parity with the Kotlin code.
- The database-backed IB1 mode uses **Ed25519 signatures**, a PostgreSQL wallet and append-only per-frame byte debit events. A byte is deducted from both voucher and wallet in one transaction. Failing database operations close the tunnel; no free mode fallback for a voucher.
- Operator-seeded **research** credit packages of 1, 5 and 10 **decimal GB** (1/5/10 billion bytes) are supported, idempotently. Only trusted provisioning may issue rights. Such rights are NOT automatically earned from home Wi-Fi or guaranteed real access.
- Each IB1 voucher expires within **24 hours** to match Android 0.13 client limitations, while the wallet persists independently. Unused expiring vouchers do not consume the wallet.
- The operator-funded lab transport is separately restricted to **5 MiB per WebSocket session**, **100 MB total billed packet payload per UTC day** through the PostgreSQL voucher path, TCP/80/443, UDP DNS/53 and four concurrent Android sockets. These limits protect the trial account; a 10 GB displayed balance is not a promise that 10 GB can be transported today.
- Free Render Postgres persists across web service restarts, but **expires 30 days after creation** and has **no managed backups**. Upgrade/migrate for real long-term use. The app's free web-service filesystem does NOT preserve a ledger. Never store credits in a local JSON/SQLite file here.
- Current participant networks are **not provisioned**. No internet path exists outside home Wi-Fi merely by virtue of this app.

## Deploy / configuration

Existing Render web service: `https://internetbattery-gateway.onrender.com` (Frankfurt, Free). Repository automatically deploys `main`. New database: `internetbattery-ledger-lab` (Frankfurt, Free), created 13 Oct 2026, expires **12 Nov 2026**.

Environment variables, configured **only in Render Dashboard**:

| Key | Usage |
| --- | --- |
| `IB_MASTER_KEY` | Existing 64-hex 32-byte secret, never commit to Git |
| `IB_DEVICE_ID` | Existing Android device ID (`ib-ae01cb519016c4` on lab service) |
| `IB_ANDROID013_COMPAT` | `1` to enable `/tunnel` |
| `IB_SESSION_BYTE_CAP` | Lab per-WebSocket cap, `5242880` |
| `DATABASE_URL` | **Internal PostgreSQL URL** from the `internetbattery-ledger-lab` Render connection screen; do not print or commit |
| `IB_CREDIT_DB_ENABLED` | `1` only **after** DATABASE_URL and trusted issuer keys are correctly set |
| `IB_ISSUER_PUBLIC_KEY_PEM` | Ed25519 SPKI public PEM for IB1 verification |
| `IB_ISSUER_PRIVATE_KEY_PEM` | Ed25519 PKCS8 private PEM for trusted web wallet issuance; keep server-only |
| `IB_VOUCHER_GATEWAY_ID` | `ib-gw1` |
| `IB_WALLET_HTTP_ENABLED` | `1` only when PostgreSQL and issuer are ready |
| `IB_LAB_SEED_PACKAGES` | Optional `1,5,10` creates **once-only simulated** 1/5/10 GB rights for configured device, with idempotent grant IDs; never interpret as earned traffic |

Free PostgreSQL credentials are **not automatically visible** to the ChatGPT Render connector. If unconfigured, credit functionality remains disabled. Never turn on `IB_CREDIT_DB_ENABLED=1` with an invalid/missing DATABASE_URL; that deliberately fails startup to prevent accidental accounting loss.

`npm ci --omit=dev && npm test` must pass in the deployed build. For local work: `npm ci && npm test`. GitHub CI starts an isolated test PostgreSQL for atomicity/restart regression; no production credentials are used.

## Web wallet for Android 0.13

Once the database is connected and flags are on:

1. Open `https://internetbattery-gateway.onrender.com/wallet` in Chrome.
2. Enter device ID and **derived device key** (not server master key). The key remains in the page; the browser signs each request locally and the server only sees HMACs.
3. Read research balance or issue a short-lived 1, 5 or 10 GB IB1 voucher.
4. In the existing Android 0.13 APK enter WSS address `wss://internetbattery-gateway.onrender.com/tunnel`, the same device ID/key and the issued IB1 voucher. First run its **WSS/DNS preflight** before switching VPN on.
5. Run a real Android VPN HTTPS test on a non-sensitive HTTPS destination. Validate actual egress through the VPN, byte counts, gateway DB debit, and after-server-restart balance. **Not tested on real hardware yet.**

Wallet POST endpoints use `X-IB-ID`, `X-IB-TS`, `X-IB-Nonce`, and `X-IB-MAC` over the canonical body SHA256+method+path, with a database nonce table. `POST /v1/wallet/balance {}` reads credited/spent bytes; `POST /v1/wallet/issue {"packageGb":1|5|10}` issues a device-bound IB1 voucher only when funded. Public `/healthz` and `/readyz` expose no secrets.

## Network pilot

Read `docs/PARTICIPANT_NETWORK_FIELD_TEST_TR.md` for the lawful, consent-based pilot. A cooperating Wi-Fi/mesh access point with an actual upstream connection is required outside home Wi-Fi. No mobile carrier quota is created, and the provider's internet/bandwidth and platform charges still apply.

## Security caveats

Research code, not audited. PBKDF master key unrelated to operator billing; session cap/country restrictions not a payment guarantee. Do not relay sensitive accounts, publicly expose device credentials, or put a database URL in source or user-visible logs. The trial cannot guarantee 1/5/10 GB throughput or unmetered access. Render Free's web service spins down when idle and the Free Postgres database expires without backup.
