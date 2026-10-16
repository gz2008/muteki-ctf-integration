#!/usr/bin/env bash
# Audit each pinned archive against its extracted tree and report missing files.
# Antivirus quarantine silently removes payload-bearing documentation, so this
# runs inside ctf-kali (symlink-aware, no Windows path limits).
#
# Usage: bash knowledge-integrity.sh [lock-file]
# Output: GAP_<name>=<missing>, MISSING_<name>=<relative path>, TOTAL_GAPS=<n>
set -uo pipefail

LOCK="${1:-/mnt/d/codex/output/muteki-ctf-integration/locks/knowledge-sources.json}"

PYTHON="$(command -v python3 || true)"
if [ -z "$PYTHON" ] && [ -x /usr/bin/python3 ]; then
  PYTHON=/usr/bin/python3
fi
if [ -z "$PYTHON" ]; then
  echo "python3 is required inside ctf-kali" >&2
  exit 3
fi

"$PYTHON" - "$LOCK" <<'PY'
import json
import sys
import zipfile
from pathlib import Path

lock_path = Path(sys.argv[1])


def to_wsl_path(value):
    """The lock stores Windows paths; this runs inside ctf-kali."""
    text = str(value)
    if len(text) > 2 and text[1] == ":":
        return Path("/mnt/" + text[0].lower() + text[2:].replace("\\", "/"))
    return Path(text)


lock = json.loads(lock_path.read_text(encoding="utf-8"))
tool_root = to_wsl_path(lock["tool_root"])
archive_root = to_wsl_path(lock["archive_root"])
total = 0
for entry in lock["entries"]:
    archive = archive_root / f"{entry['name']}-{entry['commit']}.zip"
    target = tool_root / entry["target"]
    if not archive.is_file() or not target.is_dir():
        print(f"GAP_{entry['name']}=unreadable")
        continue
    with zipfile.ZipFile(archive) as zf:
        members = [n for n in zf.namelist() if not n.endswith("/")]
        prefix = zf.namelist()[0].split("/")[0] + "/"
    missing = [n[len(prefix):] for n in members if not (target / n[len(prefix):]).exists()]
    total += len(missing)
    print(f"GAP_{entry['name']}={len(missing)}")
    for rel in missing[:25]:
        print(f"MISSING_{entry['name']}={rel}")
print(f"TOTAL_GAPS={total}")
PY
