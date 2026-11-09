#!/usr/bin/env bash
# Runs keyring-tester on a coverage build and copies out keyring.profraw.
set -euo pipefail

: "${pin:?keyring-tester-secure-lock.sh sets the test PIN this run approves prompts with}"

source .github/scripts/keyring-tester.sh

# Shows what holds the screen when the unlock tests stall, then fails the run.
stalled() {
  echo "--- focus"
  device shell dumpsys window | grep -E 'mCurrentFocus|mFocusedApp' || true
  device shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity' || true
  echo "--- system log"
  device logcat -d -s ActivityTaskManager WindowManager AuthController BiometricService \
    BiometricPrompt ActivityManager | tail -80 || true
  exit 1
}

# The unlock tests raise three prompts in turn, each approved with the test PIN.
for prompt in 1 2 3; do
  wait_for 60 "Unlock prompt $prompt shown" || stalled
  sleep 2
  device shell input text "$pin"
  device shell input keyevent 66
done
wait_for 120 'Unlock: [0-9]+ successes, [0-9]+ failures' || stalled
printf '%s\n' "$logs" | grep -E 'Unlock prompt|gated prompt|Unlock:'
[[ "$line" =~ Unlock:\ [0-9]+\ successes,\ ([0-9]+)\ failures ]]
[ "${BASH_REMATCH[1]}" = "0" ]

line=$(printf '%s\n' "$logs" | grep -E 'Coverage profile written with status -?[0-9]+' | tail -1 || true)
if [ -z "$line" ]; then
  echo "the runner logs are missing the coverage profile line" >&2
  exit 1
fi
echo "$line"
[[ "$line" =~ status\ 0$ ]]

device exec-out run-as "$package" cat files/keyring.profraw > keyring.profraw
[ -s keyring.profraw ]
