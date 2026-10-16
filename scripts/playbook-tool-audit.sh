#!/usr/bin/env bash
# Which tools the CTF playbooks name are actually callable in ctf-kali?
#
# Run this before adding tools: it turns "what is missing" into a list produced
# by the documentation that would be used to solve a challenge, instead of a
# guess. Missing entries that are real commands are the gap list.
#
# Usage: bash playbook-tool-audit.sh [playbook-dir ...]
set -uo pipefail

PLAYBOOK_DIRS=(
  /mnt/d/codex/output/muteki/skills/muteki-ctf-local-playbook
  /mnt/d/codex/ctf-suite/skill-src/ctf-competition
)
if [ "$#" -gt 0 ]; then
  PLAYBOOK_DIRS=("$@")
fi

echo "=== backticked tokens referenced by the playbooks ==="
tokens=()
for dir in "${PLAYBOOK_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r token; do
    tokens+=("$token")
  done < <(grep -rhoE '`[a-z][a-z0-9_.+-]{1,24}`' "$dir" 2>/dev/null |
             tr -d '`' | sort -u)
done
printf '%s\n' "${tokens[@]}" | sort -u | tr '\n' ' '
echo
echo

PRESENT=()
MISSING=()
for token in $(printf '%s\n' "${tokens[@]}" | sort -u); do
  case "$token" in
    *.md|*.py|*.json|*.log|*.php) continue ;;
  esac
  if command -v "$token" >/dev/null 2>&1; then
    PRESENT+=("$token")
  else
    MISSING+=("$token")
  fi
done

printf 'present (%d): %s\n\n' "${#PRESENT[@]}" "${PRESENT[*]}"
printf 'MISSING (%d): %s\n' "${#MISSING[@]}" "${MISSING[*]}"
echo
echo "Not every miss is a gap: prompt vocabulary, PHP functions and library names"
echo "land here too. Treat real command names as the work list."

echo
echo "=== python modules in the core venv ==="
for module in Crypto Cryptodome gmpy2 fpylll cysignals dnfile z3 sympy ecdsa pwn \
              angr capstone unicorn ropper PIL volatility3 regipy csvkit hashpumpy; do
  if /opt/ctf/venvs/core/bin/python -c "import $module" >/dev/null 2>&1; then
    echo "  $module: ok"
  else
    echo "  $module: MISSING"
  fi
done
