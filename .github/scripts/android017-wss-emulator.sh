#!/usr/bin/env bash
set -euo pipefail
cd "${GITHUB_WORKSPACE:-.}"
source .private/ci-connection.sh
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = '1'
target=android-src/InternetBattery_0_13/app/build/outputs/apk/debug/app-debug.apk
tests=android-src/InternetBattery_0_13/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
test -f "$target"
test -f "$tests"
adb install -r "$target" >/dev/null
adb install -r "$tests" >/dev/null
echo 'IB17_ANDROID_INSTRUMENTATION_INSTALLED'
# Only invoke the WSS/DNS test. Other Android installation smoke tests target
# the legacy 0.13 package identifier and do not apply to this lab17 variant.
timeout 150s adb shell am instrument -w -r \
  -e class com.internetbattery.RemoteWssRealNetworkTest \
  -e ib_wss "$IB_CI_WSS" \
  -e ib_device "$IB_CI_DEVICE" \
  -e ib_device_key "$IB_CI_KEY" \
  com.internetbattery.lab17.test/androidx.test.runner.AndroidJUnitRunner \
  | tee .private/ci-instrumentation-result.txt
if ! grep -q 'OK (1 test)' .private/ci-instrumentation-result.txt; then
  echo 'IB17_ANDROID_REAL_WSS_PREFLIGHT_FAILED'
  exit 1
fi
echo 'IB17_ANDROID_REAL_WSS_PREFLIGHT_SUCCESS'
# Grant only standard runtime permissions needed for user-consented VPN research.
adb shell pm grant com.internetbattery.lab17 android.permission.POST_NOTIFICATIONS
adb shell pm grant com.internetbattery.lab17 android.permission.NEARBY_WIFI_DEVICES
adb shell pm grant com.internetbattery.lab17 android.permission.ACCESS_FINE_LOCATION
echo 'IB17_EMULATOR_VPN_TRIAL_START'
timeout 210s adb shell am instrument -w -r \
  -e class com.internetbattery.RemoteWssVpnEndToEndTest \
  -e ib_wss "$IB_CI_WSS" \
  -e ib_device "$IB_CI_DEVICE" \
  -e ib_device_key "$IB_CI_KEY" \
  com.internetbattery.lab17.test/androidx.test.runner.AndroidJUnitRunner \
  | tee .private/ci-vpn-instrumentation-result.txt
if ! grep -q 'OK (1 test)' .private/ci-vpn-instrumentation-result.txt; then
  echo 'IB17_ANDROID_VPN_WSS_HTTPS_FAILED'
  exit 1
fi
echo 'IB17_ANDROID_VPN_WSS_HTTPS_SUCCESS'
