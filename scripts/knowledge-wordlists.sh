#!/usr/bin/env bash
# Provision and verify the offline wordlists and knowledge paths of the Muteki
# local tool root. Runs inside ctf-kali; the PowerShell callers pass a mode and
# a tool-root path and parse the KEY=VALUE lines below.
#
# Usage: bash knowledge-wordlists.sh <provision|check> [tool-root] [mode]
set -uo pipefail

COMMAND="${1:-provision}"
TOOL_ROOT="${2:-/mnt/d/codex/output/muteki-ctf-integration/muteki-tool-root}"
SECLISTS_MODE="${3:-symlink}"
SECLISTS_SWITCH="/usr/share/seclists"
ROCKYOU_SRC="/usr/share/wordlists/rockyou.txt.gz"
SECLISTS_TARGET="$TOOL_ROOT/wordlists/SecLists"
ROCKYOU_TARGET="$TOOL_ROOT/wordlists/kali/rockyou.txt"
FALLBACK_SUBDIRS=("Discovery/Web-Content" "Discovery/DNS" "Passwords" "Usernames" "Fuzzing")
ROCKYOU_MIN_LINES=14000000

provision_seclists() {
  if [ -L "$SECLISTS_TARGET" ]; then
    echo "SECLISTS=skip-link"
    return 0
  fi
  if [ -d "$SECLISTS_TARGET" ]; then
    echo "SECLISTS=keep-directory"
    return 0
  fi
  if [ "$SECLISTS_MODE" = "copy" ]; then
    mkdir -p "$SECLISTS_TARGET"
    cp -a "$SECLISTS_SWITCH/." "$SECLISTS_TARGET/"
    echo "SECLISTS=copied"
    return 0
  fi
  mkdir -p "$(dirname "$SECLISTS_TARGET")"
  if ln -sfn "$SECLISTS_SWITCH" "$SECLISTS_TARGET" && [ -r "$SECLISTS_TARGET/README.md" ]; then
    echo "SECLISTS=linked"
    return 0
  fi
  echo "SECLISTS=link-failed"
  mkdir -p "$SECLISTS_TARGET"
  for sub in "${FALLBACK_SUBDIRS[@]}"; do
    mkdir -p "$SECLISTS_TARGET/$(dirname "$sub")"
    cp -a "$SECLISTS_SWITCH/$sub" "$SECLISTS_TARGET/$(dirname "$sub")/"
  done
  echo "SECLISTS=copied-subset"
}

line_count() {
  local path="$1"
  if [ -r "$path" ]; then
    wc -l < "$path" | tr -d ' '
  else
    echo "0"
  fi
}

provision_rockyou() {
  if [ -f "$ROCKYOU_TARGET" ]; then
    local current
    current="$(line_count "$ROCKYOU_TARGET")"
    if [ "$current" -ge "$ROCKYOU_MIN_LINES" ]; then
      echo "ROCKYOU=skip:$current"
      return 0
    fi
    echo "ROCKYOU=rebuild:$current"
    rm -f "$ROCKYOU_TARGET"
  fi
  if [ ! -f "$ROCKYOU_SRC" ]; then
    echo "ROCKYOU=install-package"
    if ! sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y wordlists >/dev/null 2>&1; then
      echo "ROCKYOU=package-failed"
      return 1
    fi
  fi
  mkdir -p "$(dirname "$ROCKYOU_TARGET")"
  gunzip -c "$ROCKYOU_SRC" > "$ROCKYOU_TARGET"
  local lines
  lines="$(line_count "$ROCKYOU_TARGET")"
  if [ "$lines" -lt "$ROCKYOU_MIN_LINES" ]; then
    echo "ROCKYOU=short:$lines"
    return 1
  fi
  echo "ROCKYOU=ready:$lines"
}

check_all() {
  if [ -L "$SECLISTS_TARGET" ]; then
    echo "SECLISTS=link:$(readlink "$SECLISTS_TARGET")"
  elif [ -d "$SECLISTS_TARGET" ]; then
    echo "SECLISTS=directory"
  else
    echo "SECLISTS=missing"
  fi
  if [ -r "$SECLISTS_TARGET/README.md" ]; then
    echo "SECLISTS_README=ok"
  else
    echo "SECLISTS_README=bad"
  fi
  echo "RAFT_LINES=$(line_count "$SECLISTS_TARGET/Discovery/Web-Content/raft-medium-directories.txt")"
  echo "XATO_LINES=$(line_count "$SECLISTS_TARGET/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt")"
  echo "ROCKYOU_LINES=$(line_count "$ROCKYOU_TARGET")"
  echo "NUCLEI_YAML=$(find "$TOOL_ROOT/nuclei-templates" -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')"

  if [ -r "$TOOL_ROOT/env.sh" ]; then
    # shellcheck disable=SC1090,SC1091
    . "$TOOL_ROOT/env.sh" >/dev/null 2>&1 || true
  fi
  for name in MUTEKI_OFFLINE_KNOWLEDGE_DIR MUTEKI_POC_DIR MUTEKI_SECLISTS_DIR MUTEKI_WORDLIST_DIR NUCLEI_TEMPLATES; do
    value="${!name:-}"
    if [ -n "$value" ] && [ -r "$value" ]; then
      echo "ENV_${name}=ok:$value"
    else
      echo "ENV_${name}=bad:${value:-unset}"
    fi
  done
  for pair in knowledge:knowledges pocs:pocs wordlists:wordlists nuclei-templates:nuclei-templates; do
    logical="${pair%%:*}"
    dir="${pair##*:}"
    if [ -d "$TOOL_ROOT/$dir" ] && [ -n "$(ls -A "$TOOL_ROOT/$dir" 2>/dev/null)" ]; then
      echo "PROJECTION_${logical}=ok"
    else
      echo "PROJECTION_${logical}=bad"
    fi
  done
}

case "$COMMAND" in
  provision)
    provision_seclists
    provision_rockyou
    ;;
  check)
    check_all
    ;;
  *)
    echo "usage: $0 <provision|check> [tool-root] [symlink|copy]" >&2
    exit 2
    ;;
esac
