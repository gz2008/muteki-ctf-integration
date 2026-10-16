#!/usr/bin/env bash
# Keyword search across the pinned offline CTF corpora in the Muteki tool root.
# Runs inside ctf-kali (ripgrep, Linux paths). Designed for agents: compact
# "corpus:relative/path:line: snippet" output, bounded hits per corpus.
#
# Usage: corpus-search.sh [options] <pattern> [pattern ...]
set -uo pipefail

TOOL_ROOT="${CTF_TOOL_ROOT:-/mnt/d/codex/output/muteki-ctf-integration/muteki-tool-root}"
PER_CORPUS=5
TRUNCATE=200
INCLUDE_NUCLEI=0
EXPLICIT_CORPORA=""
CASE_SENSITIVE=0
PATTERNS=()

usage() {
  cat <<'EOF'
usage: ctf-corpus [options] <pattern> [pattern ...]

  -n N        max hits per corpus (default 5)
  -c LIST     corpora: all, knowledge, pocs, cloud, pwn, stego, nuclei
              (default: knowledge,pocs)
  -t          include nuclei-templates (slow, ~14k templates)
  -a          all corpora, equivalent to -c all -t
  -s          case-sensitive match (default: case-insensitive)
  -f          do not truncate matched lines
  -l          list corpora with size and file count
  -h          this help

Patterns are ripgrep regexes; several patterns are OR'ed. Prefer one distinctive
word, or a regex such as "fastbin.*dup" for compound technique names.
Options may appear before or after the pattern.

Examples:
  ctf-corpus -c web "sql injection union"      # payload notes
  ctf-corpus -c pwn "tcache poisoning"         # heap techniques
  ctf-corpus -c cloud "azure managed identity" # cloud privesc notes
  ctf-corpus -a "CVE-2021-44228"               # everything, incl. templates
EOF
}

list_corpora() {
  printf '%-28s %10s %8s  %s\n' CORPUS SIZE FILES PATH
  for pair in \
    "PayloadsAllTheThings:$TOOL_ROOT/knowledges/PayloadsAllTheThings" \
    "InternalAllTheThings:$TOOL_ROOT/knowledges/InternalAllTheThings" \
    "hacktricks:$TOOL_ROOT/knowledges/hacktricks" \
    "hacktricks-cloud:$TOOL_ROOT/knowledges/hacktricks-cloud" \
    "how2heap:$TOOL_ROOT/knowledges/how2heap" \
    "ctf-wiki:$TOOL_ROOT/knowledges/ctf-wiki" \
    "vulhub:$TOOL_ROOT/pocs/vulhub" \
    "Awesome-POC:$TOOL_ROOT/pocs/Awesome-POC" \
    "nuclei-templates:$TOOL_ROOT/nuclei-templates"; do
    name="${pair%%:*}"
    dir="${pair#*:}"
    if [ -d "$dir" ]; then
      size="$(du -sh "$dir" 2>/dev/null | cut -f1)"
      files="$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')"
    else
      size="-"
      files="0"
    fi
    printf '%-28s %10s %8s  %s\n' "$name" "$size" "$files" "$dir"
  done
}

# GNU getopt permutes, so options may follow the pattern. POSIX getopts stops at
# the first non-option argument, which silently turned `ctf-corpus -c web "x" -n 2`
# into the patterns ("x", "-n", "2") and matched anything containing a 2.
if ! PARSED="$(getopt -o n:c:tsfalh -l help -- "$@" 2>/dev/null)"; then
  usage >&2
  exit 2
fi
eval set -- "$PARSED"
while true; do
  case "$1" in
    -n) PER_CORPUS="$2"; shift 2 ;;
    -c) EXPLICIT_CORPORA="$2"; shift 2 ;;
    -t) INCLUDE_NUCLEI=1; shift ;;
    -a) EXPLICIT_CORPORA="all"; INCLUDE_NUCLEI=1; shift ;;
    -s) CASE_SENSITIVE=1; shift ;;
    -f) TRUNCATE=0; shift ;;
    -l) list_corpora; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 2
fi
PATTERNS=("$@")

if [ -z "$EXPLICIT_CORPORA" ]; then
  EXPLICIT_CORPORA="knowledge,pocs"
fi

# in_scope <corpus-name> <group,group,...> — a corpus is searched when its own
# name or one of its groups appears in -c, and always with -c all / -a.
in_scope() {
  case "$EXPLICIT_CORPORA" in
    all) return 0 ;;
  esac
  local list=",$EXPLICIT_CORPORA,"
  case "$list" in
    *",$1,"*) return 0 ;;
  esac
  local group
  for group in $(printf '%s' "$2" | tr ',' ' '); do
    case "$list" in
      *",$group,"*) return 0 ;;
    esac
  done
  return 1
}

search_corpus() {
  local label="$1"
  local dir="$2"
  [ -d "$dir" ] || return 0
  local args=(--no-ignore --hidden --line-number --max-count "$PER_CORPUS"
              --glob '!*.png' --glob '!*.jpg' --glob '!*.jpeg' --glob '!*.gif'
              --glob '!*.svg' --glob '!*.jar' --glob '!*.woff*' --glob '!*.ico')
  if [ "$CASE_SENSITIVE" -eq 0 ]; then
    args+=(--ignore-case)
  fi
  if [ "$TRUNCATE" -gt 0 ]; then
    args+=(--max-columns "$TRUNCATE" --max-columns-preview)
  fi
  local pattern
  for pattern in "${PATTERNS[@]}"; do
    args+=(-e "$pattern")
  done
  local hits
  hits="$(rg "${args[@]}" "$dir" 2>/dev/null | head -n "$PER_CORPUS")"
  [ -n "$hits" ] || return 0
  printf '%s\n' "$hits" | while IFS= read -r line; do
    printf '[%s] %s\n' "$label" "${line#"$TOOL_ROOT/"}"
  done
}

in_scope PayloadsAllTheThings "knowledge,web,pwn,crypto" &&
  search_corpus PayloadsAllTheThings "$TOOL_ROOT/knowledges/PayloadsAllTheThings"
in_scope InternalAllTheThings "knowledge,ad,redteam" &&
  search_corpus InternalAllTheThings "$TOOL_ROOT/knowledges/InternalAllTheThings"
in_scope hacktricks "knowledge,web,pwn,crypto,forensics,misc,ad" &&
  search_corpus hacktricks "$TOOL_ROOT/knowledges/hacktricks"
in_scope hacktricks-cloud "knowledge,cloud" &&
  search_corpus hacktricks-cloud "$TOOL_ROOT/knowledges/hacktricks-cloud"
in_scope how2heap "knowledge,pwn" &&
  search_corpus how2heap "$TOOL_ROOT/knowledges/how2heap"
in_scope ctf-wiki "knowledge,web,pwn,crypto,misc,reverse,blockchain,cloud" &&
  search_corpus ctf-wiki "$TOOL_ROOT/knowledges/ctf-wiki"
in_scope vulhub "pocs,web" &&
  search_corpus vulhub "$TOOL_ROOT/pocs/vulhub"
in_scope Awesome-POC "pocs,web,misc" &&
  search_corpus Awesome-POC "$TOOL_ROOT/pocs/Awesome-POC"
if [ "$INCLUDE_NUCLEI" -eq 1 ] && in_scope nuclei-templates "nuclei"; then
  search_corpus nuclei-templates "$TOOL_ROOT/nuclei-templates"
fi

exit 0
