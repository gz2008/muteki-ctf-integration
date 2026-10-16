#!/usr/bin/env bash
# Wrapper so the triage helper runs with the core venv python.
set -uo pipefail
ROOT="${CTF_INTEGRATION_ROOT:-/mnt/d/codex/output/muteki-ctf-integration}"
PYTHON="${CTF_INDEX_PYTHON:-/opt/ctf/venvs/core/bin/python}"
exec "$PYTHON" "$ROOT/scripts/ctf-triage.py" "$@"
