#!/usr/bin/env bash
set -euo pipefail
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = '1'
adb shell input keyevent 82
adb install -r internetbattery-0.17-lab.apk
adb shell pm path com.internetbattery.lab17 | tee /tmp/ib_android_pkg.txt
# Grant only runtime permissions already declared in the research APK.
adb shell pm grant com.internetbattery.lab17 android.permission.POST_NOTIFICATIONS
adb shell pm grant com.internetbattery.lab17 android.permission.ACCESS_FINE_LOCATION
adb shell pm grant com.internetbattery.lab17 android.permission.NEARBY_WIFI_DEVICES
adb shell am start -W -n com.internetbattery.lab17/com.internetbattery.MainActivity | tee /tmp/ib_android_launch.txt
sleep 15
adb logcat -d -v time -t 10000 > /tmp/ib_android_logcat.txt
pid="$(adb shell pidof com.internetbattery.lab17 | tr -d '\r')"
if [[ -z "$pid" ]]; then
  echo 'IB_ANDROID17_EMULATOR_APP_NOT_RUNNING'
  grep -E 'AndroidRuntime|FATAL EXCEPTION|com.internetbattery' /tmp/ib_android_logcat.txt | tail -50 || true
  exit 1
fi
if grep -A 8 'FATAL EXCEPTION' /tmp/ib_android_logcat.txt | grep -q 'com.internetbattery.lab17'; then
  echo 'IB_ANDROID17_EMULATOR_APP_CRASHED'
  exit 1
fi
adb shell dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity|ResumedActivity|MainActivity' | tail -8 || true
echo "IB_ANDROID17_EMULATOR_BOOT_INSTALL_LAUNCH_SUCCESS pid=$pid"
