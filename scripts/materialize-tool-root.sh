#!/usr/bin/env bash
# Build a Muteki-compatible local tool root backed by ctf-kali.
# This script only writes inside the integration directory.
set -euo pipefail

ROOT="${1:-/mnt/d/codex/output/muteki-ctf-integration}"
TOOL_ROOT="$ROOT/muteki-tool-root"
SUITE_ROOT="${CTF_SUITE_ROOT:-/mnt/d/codex/ctf-suite}"

mkdir -p "$TOOL_ROOT/bin" "$TOOL_ROOT/tools/target-binaries" \
  "$TOOL_ROOT/wordlists" "$TOOL_ROOT/pocs" "$TOOL_ROOT/knowledges" \
  "$TOOL_ROOT/nuclei-templates"

python3 - "$TOOL_ROOT" <<'PY'
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
suite = Path(os.environ.get("CTF_SUITE_ROOT", "/mnt/d/codex/ctf-suite"))
manifest = json.loads((suite / "config" / "tools.core.json").read_text(encoding="utf-8-sig"))
output = {
    "version": 1,
    "source": "D:\\\\codex\\\\ctf-suite",
    "distribution": "ctf-kali",
    "commands": [],
    "python": manifest.get("python", {}),
    "notes": [
        "Muteki local workers project this root as ./toolbox.",
        "Commands are resolved inside ctf-kali by muteki-ctf-exec.",
    ],
}
# Offline corpora pinned by locks/knowledge-sources.json; the section is data
# driven so it never drifts from the fetch lock.
knowledge_lock = root.parent / "locks" / "knowledge-sources.json"
if knowledge_lock.is_file():
    data = json.loads(knowledge_lock.read_text(encoding="utf-8"))
    output["knowledge"] = [
        {
            "name": entry.get("name", ""),
            "repository": entry.get("repository", ""),
            "commit": entry.get("commit", ""),
            "target": entry.get("target", ""),
            "license": entry.get("license", ""),
        }
        for entry in data.get("entries", [])
    ]
    output["wordlists"] = {
        name: {
            "source": value.get("source", ""),
            "target": value.get("target", ""),
        }
        for name, value in (data.get("wordlists") or {}).items()
    }
(root / "tools" / "manifest.json").write_text(
    json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

for command in $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); print(" ".join(d.get("commands", [])))' "$SUITE_ROOT/config/tools.core.json"); do
  cat > "$TOOL_ROOT/bin/$command" <<EOS
#!/usr/bin/env bash
exec "$ROOT/bin/muteki-ctf-exec" "$command" "\$@"
EOS
  chmod +x "$TOOL_ROOT/bin/$command"
done

cat > "$TOOL_ROOT/env.sh" <<EOS
export MUTEKI_LOCAL_WORKER_ROOT="$TOOL_ROOT"
export MUTEKI_MAC_WORKER_ROOT="$TOOL_ROOT"
export MUTEKI_CTF_BRIDGE_ROOT="$ROOT"
export CTF_SUITE_ROOT="$SUITE_ROOT"
if [ -d "$SUITE_ROOT/tools/hashcat-win" ]; then export MUTEKI_HASHCAT_WIN_ROOT="$SUITE_ROOT/tools/hashcat-win"; fi
# Offline corpora are exported only when the directory actually carries content,
# matching ctf-tools/env.sh so local Workers and scripts agree on the layout.
if [ -n "\$(ls -A "$TOOL_ROOT/knowledges" 2>/dev/null)" ]; then export MUTEKI_OFFLINE_KNOWLEDGE_DIR="$TOOL_ROOT/knowledges"; fi
if [ -n "\$(ls -A "$TOOL_ROOT/pocs" 2>/dev/null)" ]; then export MUTEKI_POC_DIR="$TOOL_ROOT/pocs"; fi
if [ -d "$TOOL_ROOT/wordlists/SecLists" ]; then export MUTEKI_SECLISTS_DIR="$TOOL_ROOT/wordlists/SecLists"; fi
if [ -d "$TOOL_ROOT/wordlists/kali" ]; then export MUTEKI_WORDLIST_DIR="$TOOL_ROOT/wordlists/kali"; fi
if [ -n "\$(ls -A "$TOOL_ROOT/nuclei-templates" 2>/dev/null)" ]; then export NUCLEI_TEMPLATES="$TOOL_ROOT/nuclei-templates"; fi
export PATH="$TOOL_ROOT/bin:\$PATH"
EOS

touch "$TOOL_ROOT/.ready"
printf 'materialized: %s\n' "$TOOL_ROOT"
