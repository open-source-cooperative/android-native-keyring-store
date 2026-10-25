#!/usr/bin/env bash
# Runs keyring-tester on a coverage build and copies out keyring.profraw.
set -euo pipefail

source .github/scripts/keyring-tester.sh

line=$(printf '%s\n' "$logs" | grep -E 'Coverage profile written with status -?[0-9]+' | tail -1 || true)
if [ -z "$line" ]; then
  echo "the runner logs are missing the coverage profile line" >&2
  exit 1
fi
echo "$line"
[[ "$line" =~ status\ 0$ ]]

device exec-out run-as "$package" cat files/keyring.profraw > keyring.profraw
[ -s keyring.profraw ]
