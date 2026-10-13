#!/usr/bin/env bash
set -euo pipefail
cd "${GITHUB_WORKSPACE:-.}"
mkdir -p .private android-src

# Immutable 0.13 source recovery and the exact 0.17 overlay under review.
source_url='https://5tgvowvfduadsxzq.public.blob.vercel-storage.com/InternetBattery_0_13_Source_And_Verification.zip?download=1'
curl --fail --location --silent --show-error --retry 3 --max-time 120 "$source_url" -o .private/original-0.13.zip
printf '%s  %s\n' '620eae8a291caf3bc397a499c39a2c3e7d6879129ef47eb48a31adbf19f03a8c' '.private/original-0.13.zip' | sha256sum -c -
python3 - <<'PY'
from pathlib import Path, PurePosixPath
from zipfile import ZipFile
import shutil
root=Path('android-src')
with ZipFile('.private/original-0.13.zip') as source:
    total=0
    for entry in source.infolist():
        p=PurePosixPath(entry.filename)
        if p.is_absolute() or '..' in p.parts or len(p.parts)>18:raise SystemExit('Unsafe ZIP entry')
        if entry.is_dir():continue
        total+=entry.file_size
        if total>1_000_000_000:raise SystemExit('Archive extraction limit')
        out=root.joinpath(*p.parts)
        out.parent.mkdir(parents=True,exist_ok=True)
        with source.open(entry) as src,open(out,'wb') as dst:shutil.copyfileobj(src,dst)
p=root/'InternetBattery_0_13'
if not (p/'settings.gradle.kts').exists():raise SystemExit('Android source missing')
gradle=p/'app/build.gradle.kts'
t=gradle.read_text()
assert 'applicationId = "com.internetbattery"' in t
t=t.replace('applicationId = "com.internetbattery"','applicationId = "com.internetbattery.lab17"')
t=t.replace('versionCode = 13','versionCode = 17').replace('versionName = "0.13.0-lab"','versionName = "0.17.0-lab"')
gradle.write_text(t)
ui=p/'app/src/main/java/com/internetbattery/MainActivity.kt'
v=ui.read_text()
v=v.replace('mutableStateOf("") }\n    var probeResult', 'mutableStateOf("wss://internetbattery-gateway.onrender.com/tunnel") }\n    var probeResult')
v=v.replace('mutableStateOf("ib") }\n    var ib1Voucher','mutableStateOf("ib-ae01cb519016c4") }\n    var ib1Voucher')
v=v.replace('INTERNET BATTERY 0.13','INTERNET BATTERY LAB 0.17')
v=v.replace('var clientSecret by remember { mutableStateOf("") }','var clientSecret by remember { mutableStateOf(LabKeyStore.read(context)) }')
v=v.replace('onValueChange={clientSecret=it.trim()}', 'onValueChange={ clientSecret=it.trim(); if(clientSecret.isBlank()) LabKeyStore.clear(context) else LabKeyStore.save(context,clientSecret) }')
ui.write_text(v)
(p/'app/src/main/java/com/internetbattery/LabKeyStore.kt').write_text(Path('android/overlays/LabKeyStore.kt').read_text())
manifest=p/'app/src/main/AndroidManifest.xml'
manifest.write_text(manifest.read_text().replace('android:label="Internet Battery"','android:label="Internet Battery LAB 0.17"'))
test=p/'app/src/androidTest/java/com/internetbattery/RemoteWssRealNetworkTest.kt'
test.parent.mkdir(parents=True,exist_ok=True)
test.write_text(Path('android/verification/RemoteWssRealNetworkTest.kt').read_text())
vpn_test=p/'app/src/androidTest/java/com/internetbattery/RemoteVpnRealNetworkTest.kt'
vpn_test.write_text(Path('android/verification/RemoteVpnRealNetworkTest.kt').read_text())
# Ephemeral diagnostic only; no changes to shipped 0.17 source/APK.
vpn_source=p/'app/src/main/java/com/internetbattery/TunnelVpnService.kt'
vpn_text=vpn_source.read_text()
old_catch='}catch(e:Exception){'+chr(10)+'                RuntimeStatus.update { it.copy(vpnMessage="Uzak WSS VPN hatası: "+e.message,'
new_catch='}catch(e:Exception){'+chr(10)+'                android.util.Log.e("IB17_VPN_DIAG", "Remote VPN stack trace", e)'+chr(10)+'                RuntimeStatus.update { it.copy(vpnMessage="Uzak WSS VPN hatası: "+e.message,'
if vpn_text.count(old_catch)!=1:raise SystemExit('VPN catch diagnostic anchor invalid')
vpn_text=vpn_text.replace(old_catch,new_catch)
legacy_loopback='builder.excludeRoute(IpPrefix(InetAddress.getByName("127.0.0.1"),32))'
if vpn_text.count(legacy_loopback)!=1:raise SystemExit('Expected exactly one invalid loopback VPN route')
# Android VpnService.Builder rejects loopback prefixes with Bad address.
# Local SOCKS5 sockets are already local; outbound WSS uses protected underlay.
vpn_text=vpn_text.replace(legacy_loopback,'// Loopback SOCKS5 stays local; VpnService rejects excluding loopback routes.')
vpn_source.write_text(vpn_text)
# Native tun2socks diagnostic overlay only: no private values printed.
hev_source=p/'app/src/main/java/com/internetbattery/HevEngine.kt'
hev=hev_source.read_text()
old='if (!started) onStatus("Native tun2socks başlatma başarısız")'
new='if (!started) { Log.e("IB17_HEV_DIAG", "TProxyStartService returned false"); onStatus("Native tun2socks başlatma başarısız") }'
if hev.count(old)!=1:raise SystemExit('Unexpected HevEngine start source')
hev=hev.replace(old,new)
old='Log.e("InternetBattery", "Native tunnel failure", e)'
new='Log.e("IB17_HEV_DIAG", "Native tunnel exception", e)'
if hev.count(old)!=1:raise SystemExit('Unexpected HevEngine exception source')
hev=hev.replace(old,new)
old='catch (_: Throwable) { false }'
new='catch (e: Throwable) { Log.e("IB17_HEV_DIAG", "TProxyIsRunning JNI exception", e); false }'
if hev.count(old)!=1:raise SystemExit('Unexpected JNI state source')
hev=hev.replace(old,new)

# CI-only native logging in the app sandbox. Never emit a complete YAML config,
# key or password. The diagnostic log is not bundled into Android releases.
log_before='                  log-level: warn'
log_after='                  log-level: debug'+chr(10)+'                  log-file: '+chr(39)+chr(36)+'{context.filesDir}/ib-native-engine.log'+chr(39)
if hev.count(log_before)!=1:raise SystemExit('Unexpected Hev logging anchor')
hev=hev.replace(log_before,log_after)
call_before='val started = TProxyService.TProxyStartService(conf.absolutePath, fd)'
call_after='Log.i("IB17_HEV_DIAG", "Invoking native TUN service, fd="+fd+", configFound="+conf.exists())'+chr(10)+'                    '+call_before
if hev.count(call_before)!=1:raise SystemExit('Unexpected TProxy invocation')
hev=hev.replace(call_before,call_after)

# IMPORTANT: upstream hev JNI starts a native pthread and returns immediately.
# The original Kotlin finally block deletes the YAML before the pthread
# executes hev_config_init_from_file(), causing sporadic startup failure.
racy='''                } finally {
                    synchronized(guard) {
                        if (configFile == conf) { conf.delete(); configFile = null }
                    }
                }'''
fixed='''                } finally {
                    // JNI worker is asynchronous; keep the YAML until stop().
                }'''
if hev.count(racy)!=1:raise SystemExit('Original premature-delete block not found exactly once')
hev=hev.replace(racy,fixed)
print('IB17_HEV_CONFIG_RACE_FIXED')

# CI-only routing isolation prevents Android system background applications
# from exhausting the 4-connection trial gateway during app HTTPS acceptance.
vpn_limited='                    .setUnderlyingNetworks(arrayOf(underlying))'
vpn_isolated=vpn_limited+chr(10)+'                    .addAllowedApplication(packageName)'
if vpn_text.count(vpn_limited)!=1:raise SystemExit('Expected one Android VPN underlay declaration')
vpn_text=vpn_text.replace(vpn_limited,vpn_isolated)
vpn_source.write_text(vpn_text)
# Annotate only address-family, destination port and gateway denial reasons.
# No hostnames, URLs, user credentials or packet payloads are logged.
bridge_source=p/'app/src/main/java/com/internetbattery/WssSocksBridge.kt'
bridge=bridge_source.read_text()
tcp_anchor='''        val out=sock.getOutputStream()
        if(port!=80&&port!=443)'''
tcp_diag='''        val out=sock.getOutputStream()
        val family = if(host.contains(':')) "ipv6" else if(host.all { it.isDigit() || it=='.' }) "ipv4" else "domain"
        android.util.Log.w("IB17_BRIDGE_DIAG","tcp_request family="+family+" port="+port)
        if(port!=80&&port!=443)'''
if bridge.count(tcp_anchor)!=1:raise SystemExit('SOCKS bridge entry changed')
bridge=bridge.replace(tcp_anchor,tcp_diag)
err_anchor='''                    "error","quota"->{connected.complete(false);runCatching{sock.close()}}'''
err_diag='''                    "error","quota"->{android.util.Log.w("IB17_BRIDGE_DIAG","tcp_gateway_denial="+runCatching{JSONObject(text).optString("error")}.getOrDefault("unknown"));connected.complete(false);runCatching{sock.close()}}'''
if bridge.count(err_anchor)!=1:raise SystemExit('SOCKS error handler changed')
bridge=bridge.replace(err_anchor,err_diag)
fail_anchor='''                connected.complete(false);runCatching{sock.close()}
            }
            override fun onClosed'''
fail_diag='''                android.util.Log.w("IB17_BRIDGE_DIAG","tcp_ws_failure status="+(r?.code ?: 0)+" reason="+t.javaClass.simpleName)
                connected.complete(false);runCatching{sock.close()}
            }
            override fun onClosed'''
if bridge.count(fail_anchor)!=1:raise SystemExit('SOCKS websocket failure anchor changed')
bridge=bridge.replace(fail_anchor,fail_diag)
bridge_source.write_text(bridge)
print('IB17_VPN_APP_ONLY_AND_BRIDGE_DIAGNOSTICS_ADDED')
hev_source.write_text(hev)
print("ANDROID17_TEST_SOURCE_PREPARED")
PY

# This ephemeral gateway has no real credits and no database. Never persist keys.
npm ci --omit=dev --ignore-scripts
master="$(openssl rand -hex 32)"
device="ib-android-ci"
key="$(IB_TMP_MASTER="$master" IB_TMP_DEVICE="$device" node --input-type=module -e '
import {createHmac} from "node:crypto";
const master=Buffer.from(process.env.IB_TMP_MASTER,"hex");
process.stdout.write(createHmac("sha256",master).update("IB09-device:"+process.env.IB_TMP_DEVICE).digest("hex"));
')"
echo "::add-mask::$master"
echo "::add-mask::$key"
RUNNER_TRACKING_ID='' IB_MASTER_KEY="$master" IB_DEVICE_ID="$device" IB_ANDROID013_COMPAT=1 IB_SESSION_BYTE_CAP=8388608 PORT=18600 \
  nohup node server.mjs > .private/ephemeral-gateway.log 2>&1 < /dev/null &
echo $! > .private/gateway.pid
for i in $(seq 1 40); do if curl --fail --silent http://127.0.0.1:18600/readyz | grep -q '"ready":true';then break;fi;sleep 1;done
curl --fail --silent http://127.0.0.1:18600/readyz | grep -q '"android013LabCompatibility":true'

# Cloudflare quick tunnel provides a temporary, publicly trusted HTTPS/WSS
# endpoint, allowing the Android emulator to exercise real TLS and the app's
# original WssCredentials and RemoteWssProbe without changing production.
curl --fail --location --silent --show-error --retry 3 --max-time 120 \
  https://github.com/cloudflare/cloudflared/releases/download/2026.10.0/cloudflared-linux-amd64 \
  -o .private/cloudflared
printf '%s  %s\n' 'd33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db' '.private/cloudflared' | sha256sum -c -
chmod 700 .private/cloudflared
RUNNER_TRACKING_ID='' nohup .private/cloudflared tunnel --no-autoupdate --url http://127.0.0.1:18600 \
  > .private/cloudflared.log 2>&1 < /dev/null &
echo $! > .private/cloudflared.pid
hostname=''
for i in $(seq 1 120);do
 hostname="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' .private/cloudflared.log | head -1 || true)"
 if [[ -n "$hostname" ]]; then break;fi
 sleep 1
done
if [[ -z "$hostname" ]]; then
 echo 'IB_CI_CLOUDFLARE_TUNNEL_UNAVAILABLE'
 tail -15 .private/cloudflared.log | sed -E 's/(token|secret|credential)=[^ ]+/\1=REDACTED/g'
 exit 1
fi
echo "IB_CI_PUBLIC_WSS_HOST_CONNECTED: ${hostname#https://}"
for i in $(seq 1 70);do
 if curl --fail --location --silent --show-error --max-time 8 "$hostname/healthz" 2>/dev/null | grep -q '"status":"alive"';then break;fi
 sleep 2
done
curl --fail --location --silent --show-error --max-time 15 "$hostname/readyz" | grep -q '"android013LabCompatibility":true'
wss="wss://${hostname#https://}/tunnel"
printf 'export IB_CI_WSS=%q\nexport IB_CI_DEVICE=%q\nexport IB_CI_KEY=%q\n' "$wss" "$device" "$key" > .private/ci-connection.sh
chmod 600 .private/ci-connection.sh
echo "IB_CI_TLS_WSS_GATEWAY_READY"
