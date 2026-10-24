#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_KNOWLEDGE=0
SKIP_VERIFY=0

usage() {
  cat <<'EOF'
Usage: ./bootstrap.sh [options]

Options:
  --with-knowledge   Download pinned offline corpora (Windows/WSL only for now)
  --skip-verify      Skip the Python syntax and ctf-triage smoke test
  -h, --help         Show this help

The default is core-only: no large downloads and no system changes.
EOF
}

while (($#)); do
  case "$1" in
    --with-knowledge) WITH_KNOWLEDGE=1 ;;
    --skip-verify) SKIP_VERIFY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done

step() { printf '\n==> %s\n' "$1"; }
ok() { printf 'OK  %s\n' "$1"; }
warn() { printf 'WARN %s\n' "$1"; }

step "Checking Python"
PYTHON=""
for candidate in "${CTF_LOCAL_PYTHON:-}" python3 python py.exe py; do
  [[ -n "$candidate" ]] || continue
  if [[ "$candidate" == */* || "$candidate" == *\\* ]]; then
    resolved="$candidate"
  else
    resolved="$(command -v "$candidate" 2>/dev/null || true)"
  fi
  [[ -n "$resolved" ]] || continue
  if "$resolved" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    PYTHON="$resolved"
    break
  fi
done
if [[ -z "$PYTHON" ]]; then
  echo "Python 3.10+ was not found." >&2
  exit 2
fi
ok "$("$PYTHON" --version 2>&1)"

for required in \
  "studio/server.py" \
  "studio/web/index.html" \
  "scripts/ctf-triage.py"; do
  if [[ ! -f "$ROOT/$required" ]]; then
    echo "Incomplete checkout: missing $required" >&2
    exit 2
  fi
done
ok "Core files are present"

if [[ "$SKIP_VERIFY" -eq 0 ]]; then
  step "Running core verification"
  "$PYTHON" -m py_compile \
    "$ROOT/studio/server.py" \
    "$ROOT/studio/desktop.py"
  "$PYTHON" "$ROOT/scripts/ctf-triage.py" --json "$ROOT/README.md" >/dev/null
  ok "Python sources compile and ctf-triage runs"
fi

if [[ "$WITH_KNOWLEDGE" -eq 1 ]]; then
  step "Installing offline knowledge corpora"
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*)
      if ! command -v pwsh >/dev/null 2>&1; then
        echo "PowerShell 7 is required for corpus provisioning on Windows." >&2
        exit 2
      fi
      pwsh -NoProfile -File "$ROOT/scripts/fetch-knowledge.ps1"
      pwsh -NoProfile -File "$ROOT/scripts/verify-knowledge.ps1"
      ;;
    *)
      echo "Corpus provisioning currently uses the Windows/WSL pipeline." >&2
      echo "Linux/macOS users can use the standalone Python analyzers without it." >&2
      exit 2
      ;;
  esac
fi

printf '\nBootstrap complete.\n'
printf 'Launch the local web UI with:\n'
printf '  %q %q --open\n' "$PYTHON" "$ROOT/studio/server.py"
printf 'Windows users can also run: bin\\ctf-studio.cmd\n'
if [[ "$WITH_KNOWLEDGE" -eq 0 ]]; then
  printf 'Optional corpus setup (Windows/WSL): ./bootstrap.sh --with-knowledge\n'
fi
