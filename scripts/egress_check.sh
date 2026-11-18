#!/usr/bin/env bash
# Standalone egress check for the isolated lab network (Linux/manual equivalent of the
# check built into `lab.py up`). Exits non-zero if the lab network can reach the internet.
#
# Usage:  scripts/egress_check.sh [network_name]   (default: labnet)
set -euo pipefail

NET="${1:-labnet}"

out="$(docker run --rm --network "$NET" alpine:3.20 sh -lc \
  'timeout 4 wget -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo EGRESS || echo NOEGRESS' \
  2>/dev/null || true)"

if echo "$out" | grep -q NOEGRESS; then
  echo "PASS: '$NET' has no egress."
  exit 0
fi
echo "FAIL: '$NET' appears to reach the internet (output: $out). Refuse to run — see SAFETY.md." >&2
exit 1
