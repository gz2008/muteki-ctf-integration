#!/usr/bin/env bash
set -uo pipefail
ROOT="${CTF_INTEGRATION_ROOT:-/mnt/d/codex/output/muteki-ctf-integration}"
PYTHON="${CTF_INDEX_PYTHON:-/opt/ctf/venvs/core/bin/python}"
exec "$PYTHON" "$ROOT/scripts/ctf-repair.py" "$@"
