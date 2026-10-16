#!/usr/bin/env bash
# Runs keyring-tester on a coverage build and copies out keyring.profraw.
set -euo pipefail

.github/scripts/keyring-tester.sh

line=""
for _ in $(seq 1 24); do
  line=$(adb logcat -d -s unit-test | grep -E "Coverage profile written with status -?[0-9]+" | tail -1 || true)
  [ -n "$line" ] && break
  sleep 5
done
if [ -z "$line" ]; then
  echo "keyring-tester never reported writing its coverage profile" >&2
  exit 1
fi
echo "$line"
[[ "$line" =~ status\ 0$ ]]

adb exec-out run-as com.brotsky.android.testing.keyring cat files/keyring.profraw > keyring.profraw
[ -s keyring.profraw ]
