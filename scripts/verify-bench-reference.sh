#!/usr/bin/env bash
# Reference-solve every challenge in the local benchmark set inside ctf-kali.
#
# Why this exists: a benchmark task can be broken in two ways that both look
# like "the agent failed" - the challenge ships its flag in plain sight, or the
# task cannot be solved at all with the shipped files. Both were found the hard
# way (a pcap whose flag sat in the request URI, a pwn task whose flag.txt the
# harness strips). Run this before trusting any agentic measurement.
#
# Usage: verify-bench-reference.sh
# Exit: 0 when every challenge is solved by its own reference solver with the
#       manifest's flag; 1 when any challenge fails; 2 when the set cannot be
#       read at all.
set -uo pipefail

SUITE_ROOT="${CTF_SUITE_ROOT:-/mnt/d/codex/ctf-suite}"
PY="${CTF_BENCH_PYTHON:-/opt/ctf/venvs/core/bin/python}"
LOCAL_ROOT="$SUITE_ROOT/benchmarks/local"
MANIFEST="$LOCAL_ROOT/manifest.json"

if [ ! -f "$MANIFEST" ]; then
  echo "verify-bench-reference: manifest not found: $MANIFEST" >&2
  exit 2
fi
if [ ! -x "$PY" ]; then
  echo "verify-bench-reference: python not executable: $PY" >&2
  exit 2
fi

# Read ids and expected flags without requiring jq to be installed.
mapfile -t ids < <("$PY" - "$MANIFEST" <<'PY'
import json, sys
for test in json.load(open(sys.argv[1], encoding="utf-8"))["tests"]:
    print(test["id"])
PY
)
mapfile -t flags < <("$PY" - "$MANIFEST" <<'PY'
import json, sys
for test in json.load(open(sys.argv[1], encoding="utf-8"))["tests"]:
    print(test["flag"])
PY
)

if [ "${#ids[@]}" -eq 0 ]; then
  echo "verify-bench-reference: manifest lists no tests" >&2
  exit 2
fi

failures=0
for index in "${!ids[@]}"; do
  id="${ids[$index]}"
  expected="${flags[$index]}"
  dir="$LOCAL_ROOT/$id"
  if [ ! -f "$dir/solve.py" ]; then
    printf '== %-26s FAIL  no reference solve.py\n' "$id"
    failures=$((failures + 1))
    continue
  fi
  if ! output=$(cd "$dir" && timeout 180 "$PY" solve.py 2>&1); then
    printf '== %-26s FAIL  reference solver errored: %s\n' "$id" "$(printf '%s' "$output" | tail -1)"
    failures=$((failures + 1))
    continue
  fi
  if printf '%s' "$output" | grep -qF "$expected"; then
    printf '== %-26s OK    %s\n' "$id" "$expected"
  else
    printf '== %-26s FAIL  expected %s, solver printed: %s\n' "$id" "$expected" "$(printf '%s' "$output" | tail -1)"
    failures=$((failures + 1))
  fi
done

if [ "$failures" -gt 0 ]; then
  echo "verify-bench-reference: $failures of ${#ids[@]} challenges failed" >&2
  exit 1
fi
echo "verify-bench-reference: ${#ids[@]}/${#ids[@]} challenges OK"
