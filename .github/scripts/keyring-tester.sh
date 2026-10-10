#!/usr/bin/env bash
# Installs the keyring-tester APK on the running emulator, waits for its
# "Overall" logcat line and fails unless it reports zero failures.
set -euo pipefail

adb install -r keyring-tester/app/build/outputs/apk/debug/app-debug.apk
adb shell wm dismiss-keyguard
adb shell am start -n com.brotsky.android.testing.keyring/.MainActivity

line=""
for _ in $(seq 1 60); do
  line=$(adb logcat -d -s unit-test | grep -E "Overall: [0-9]+ successes, [0-9]+ failures" | tail -1 || true)
  [ -n "$line" ] && break
  sleep 5
done

adb logcat -d -s unit-test
if [ -z "$line" ]; then
  echo "keyring-tester never reported an Overall line" >&2
  exit 1
fi
echo "$line"
[[ "$line" =~ Overall:\ [0-9]+\ successes,\ ([0-9]+)\ failures ]]
[ "${BASH_REMATCH[1]}" = "0" ]
