#!/usr/bin/env bash
# Semantic-ish lookup over the pinned offline CTF corpora (BM25, natural
# language). Complements corpus-search.sh: use ripgrep when you know the
# keyword, use this when you only know the symptom.
#
# Usage: corpus-index.sh query "how do I exploit a tcache use after free" [-n 5]
#        corpus-index.sh build        # rebuild after changing the corpora
set -uo pipefail

ROOT="${CTF_INTEGRATION_ROOT:-/mnt/d/codex/output/muteki-ctf-integration}"
PYTHON="${CTF_INDEX_PYTHON:-/opt/ctf/venvs/core/bin/python}"
INDEX_DIR="${CTF_INDEX_DIR:-$ROOT/index/bm25}"

usage() {
  cat <<'EOF'
usage: ctf-index query "<question>" [-n N] [--no-dedupe]
       ctf-index build
       ctf-index info

  query   ranked passages for a natural-language question (default N=5)
  build   rebuild the BM25 index from the corpora in the tool root (~4 min)
  info    show index location and size

The index covers the prose corpora only: PayloadsAllTheThings,
InternalAllTheThings, hacktricks, hacktricks-cloud, how2heap, vulhub and
Awesome-POC. nuclei templates and images are intentionally excluded.
EOF
}

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 2
fi

cmd="$1"
shift

# A bare question is the common case ("ctf-index tcache poisoning"), so treat
# anything that is not a known subcommand as the start of a query.
case "$cmd" in
  build|query|info|-h|--help|help) ;;
  *)
    set -- "$cmd" "$@"
    cmd="query"
    ;;
esac

case "$cmd" in
  build)
    exec "$PYTHON" "$ROOT/scripts/corpus-index.py" build --out "$INDEX_DIR"
    ;;
  query)
    if [ "$#" -eq 0 ]; then
      usage >&2
      exit 2
    fi
    args=("$@")
    # Default result count unless the caller passed an explicit -n.
    case " ${args[*]} " in
      *" -n "*) ;;
      *) args+=(-n 5) ;;
    esac
    exec "$PYTHON" "$ROOT/scripts/corpus-index.py" query "${args[@]}" --out "$INDEX_DIR"
    ;;
  info)
    if [ -f "$INDEX_DIR/meta.json" ]; then
      du -sh "$INDEX_DIR"
      printf 'index: %s\n' "$INDEX_DIR"
    else
      echo "no index at $INDEX_DIR; run: ctf-index build" >&2
      exit 1
    fi
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
