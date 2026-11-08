#!/usr/bin/env bash
set -euo pipefail

package="com.brotsky.android.testing.keyring"
run=$(od -An -vN16 -tx1 /dev/urandom | tr -d ' \n')
device() { timeout 30 adb "$@"; }

wait_for() {
  local deadline=$(( $(cut -d. -f1 /proc/uptime) + $1 ))
  while [ "$(cut -d. -f1 /proc/uptime)" -lt "$deadline" ]; do
    logs=$(device logcat -d -s unit-test)
    line=$(printf '%s\n' "$logs" | grep -E "$2" | tail -1 || true)
    [ -n "$line" ] && return 0
    sleep 2
  done
  printf '%s\n' "$logs"
  echo "keyring-tester timed out waiting for $2" >&2
  return 1
}

device install -r keyring-tester/app/build/outputs/apk/debug/app-debug.apk
device shell wm dismiss-keyguard
device shell am force-stop "$package"
device logcat -c
device shell cmd deviceidle tempwhitelist -d 30000 "$package"
device shell am startservice -n "$package/.ExplicitContextService" --es run "$run"
wait_for 120 "Explicit prepare (done|failed) run=$run"
if [[ "$line" != *"prepare done"* ]]; then
  printf '%s\n' "$logs"
  exit 1
fi

device shell am start -n "$package/.MainActivity" --es run "$run" --ez context-tested true
wait_for 300 "Explicit foreground done run=$run"
printf '%s\n' "$logs"
line=$(printf '%s\n' "$logs" | grep -E 'Overall: [0-9]+ successes, [0-9]+ failures' | tail -1)
[[ "$line" =~ Overall:\ [0-9]+\ successes,\ ([0-9]+)\ failures ]]
[ "${BASH_REMATCH[1]}" = "0" ]
