#!/usr/bin/env bash
set -euo pipefail
cd "${GITHUB_WORKSPACE:-.}"
source .private/ci-connection.sh
echo 'IB17_ANDROID_VPN_E2E_BEGIN'
adb shell am start -W -n com.internetbattery.lab17/com.internetbattery.MainActivity >/dev/null
# Android system VPN permission remains a real runtime consent operation.
# AppOps optimization is optional; if consent is still needed Android displays
# its real system confirmation dialog for the test runner to approve.
adb shell appops set com.internetbattery.lab17 ACTIVATE_VPN allow || true
set +e
timeout 165s adb shell am instrument -w -r \
  -e class com.internetbattery.RemoteVpnRealNetworkTest \
  -e ib_wss "$IB_CI_WSS" \
  -e ib_device "$IB_CI_DEVICE" \
  -e ib_device_key "$IB_CI_KEY" \
  com.internetbattery.lab17.test/androidx.test.runner.AndroidJUnitRunner \
  > .private/ci-vpn-instrumentation-result.txt 2>&1 &
instrument_pid=$!
set -e
for i in $(seq 1 135); do
  if ! kill -0 "$instrument_pid" 2>/dev/null; then break; fi
  # If Android asks for real VPN approval, click the positive system button.
  # No permission is bypassed in the application.
  adb shell uiautomator dump /sdcard/ib_vpn_window.xml >/dev/null 2>&1 || true
  adb pull /sdcard/ib_vpn_window.xml .private/ib_vpn_window.xml >/dev/null 2>&1 || true
  coords="$(python3 - <<'PY'
from pathlib import Path
from xml.etree import ElementTree as ET
import re
p=Path('.private/ib_vpn_window.xml')
if not p.exists():raise SystemExit(0)
try:
 root=ET.parse(p).getroot()
except Exception: raise SystemExit(0)
all_nodes=list(root.iter('node'))
page=' '.join(n.attrib.get('text','') for n in all_nodes).lower()
# Only approve an actual system VPN dialog; never arbitrary UI prompts.
if not any(x in page for x in ('vpn','connection request','network traffic')):
 raise SystemExit(0)
for n in all_nodes:
  txt=n.attrib.get('text','').strip().lower()
  rid=n.attrib.get('resource-id','')
  if txt in ('ok','allow','connect','approve','continue','tamam','izin ver') or rid.endswith(':id/button1'):
    b=re.findall(r'\[(\d+),(\d+)\]',n.attrib.get('bounds',''))
    if len(b)==2:
      x=(int(b[0][0])+int(b[1][0]))//2
      y=(int(b[0][1])+int(b[1][1]))//2
      print(x,y)
      break
PY
)"
  if [[ -n "$coords" ]];then
     echo 'IB17_ANDROID_SYSTEM_VPN_CONSENT_DIALOG_APPROVED'
     adb shell input tap $coords || true
     sleep 2
  fi
  sleep 1
done
set +e
wait "$instrument_pid"
rc=$?
set -e
# Present a credential-free test summary.
sed -E 's/[a-f0-9]{64}/[REDACTED_64HEX]/g' .private/ci-vpn-instrumentation-result.txt | tail -70
if [[ "$rc" -ne 0 ]] || ! grep -q 'OK (1 test)' .private/ci-vpn-instrumentation-result.txt; then
   echo 'IB17_ANDROID_VPN_WSS_HTTPS_NOT_VERIFIED'
   adb logcat -d -v time -s IB17_VPN_DIAG:E | tail -55 || true
   exit 1
fi
echo 'IB17_ANDROID_VPN_WSS_HTTPS_VERIFIED'
