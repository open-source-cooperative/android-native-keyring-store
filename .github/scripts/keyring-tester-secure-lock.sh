#!/usr/bin/env bash
# Collects coverage with a temporary test PIN on a disposable emulator.
set -euo pipefail

pin="4321"
owned=0
stayon=0

device() { timeout 30 adb "$@"; }

cleanup() {
  local status=$?
  local failed=0
  if [ "$owned" = 1 ]; then
    if ! device shell locksettings clear --old "$pin" > /dev/null; then
      echo "failed to clear the test PIN from the emulator" >&2
      failed=1
    elif device shell locksettings verify --old "$pin" > /dev/null 2>&1; then
      echo "the test PIN is still accepted after cleanup" >&2
      failed=1
    fi
  fi
  if [ "$stayon" = 1 ]; then
    device shell svc power stayon false > /dev/null || true
  fi
  if [ "$failed" = 1 ]; then
    if [ "$status" -eq 0 ]; then
      exit 1
    fi
    echo "the PIN cleanup failed in addition to the test failure" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

qemu=$(device shell getprop ro.kernel.qemu)
if [ "$qemu" != "1" ]; then
  echo "refusing to change credentials on a non-emulator device (ro.kernel.qemu=${qemu:-unset})" >&2
  exit 1
fi

# Without `--old`, `set-pin` refuses an existing lock credential.
device shell locksettings set-pin "$pin"
owned=1
device shell locksettings verify --old "$pin"

# Reads the whole dump, since `grep -q` would stop early and fail the pipe under pipefail.
keyguard_showing() {
  device shell dumpsys activity activities | grep 'mKeyguardShowing=true' > /dev/null
}

# Authenticate after configuring the credential and before starting the service. A slow
# emulator can miss the PIN while the keyguard is still coming up, so retry until it is gone.
device shell input keyevent 26
sleep 1
device shell input keyevent 26
sleep 1
for _ in 1 2 3 4 5; do
  keyguard_showing || break
  device shell input keyevent 224
  device shell wm dismiss-keyguard
  sleep 2
  device shell input text "$pin"
  device shell input keyevent 66
  sleep 2
done
if keyguard_showing; then
  echo "the keyguard is still showing after entering the test PIN" >&2
  exit 1
fi
device shell svc power stayon true
stayon=1

source .github/scripts/keyring-tester-coverage.sh
