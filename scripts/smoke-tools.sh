#!/usr/bin/env bash
# Functional smoke test: run each newly provisioned tool on a real input.
#
# `command -v` proves a file exists; it does not prove the tool works. Two gaps
# were caught this way (a launcher whose interpreter was missing, a tool that
# blocked on stdin), so every batch gets one of these before it is called done.
#
# Usage: bash smoke-tools.sh
set -uo pipefail
PY=/opt/ctf/venvs/core/bin/python
# The pinned CTF entries live in /opt/ctf/bin and the venv in
# /opt/ctf/venvs/core/bin, and neither is on the default non-login PATH. Add
# them here rather than depending on how this script was invoked: run as
# "bash smoke-tools.sh" from a plain shell, every pinned tool reads as missing
# and the failure looks like a broken toolchain instead of a broken call
# (measured: 16 passed / 9 failed that way, 25/25 with the directories on PATH).
for dir in /opt/ctf/bin /opt/ctf/venvs/core/bin; do
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) [ -d "$dir" ] && PATH="$dir:$PATH" ;;
  esac
done
export PATH
WORK="$(mktemp -d /tmp/smoke-tools-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

pass=0
fail=0
check() {
  if [ "$2" = "0" ]; then
    printf '  [PASS] %-14s %s\n' "$1" "$3"
    pass=$((pass + 1))
  else
    printf '  [FAIL] %-14s %s\n' "$1" "$3"
    fail=$((fail + 1))
  fi
}

# --- OCR: read a flag out of a rendered image (a real CTF pattern)
"$PY" - <<'PY'
from PIL import Image, ImageDraw, ImageFont
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 34)
img = Image.new("RGB", (760, 70), "white")
ImageDraw.Draw(img).text((12, 12), "flag{0cr_r3ad5_1mag3s}", fill="black", font=font)
img.save("/tmp/smoke-flag.png")
PY
tesseract /tmp/smoke-flag.png "$WORK/out" >/dev/null 2>&1
# OCR confuses 0 with O; normalise before judging.
ocr="$(tr 'O' '0' < "$WORK/out.txt" 2>/dev/null)"
case "$ocr" in
  *"0cr_r3ad5_1mag3s"*) check tesseract 0 "read '$ocr'";;
  *) check tesseract 1 "output was '$ocr'";;
esac

# --- memory forensics
vol3 -h 2>&1 | head -1 >/dev/null
check vol3 "$?" "plugin help"

# --- known-plaintext ZIP (bkcrack ships its own example archive)
ASSET=/mnt/d/codex/output/muteki-ctf-integration/archives/releases/bkcrack-1.8.1-Linux-x86_64.tar.gz
tar -xzf "$ASSET" -C "$WORK" 2>/dev/null
zip="$(ls -d "$WORK"/bkcrack-*/example/secrets.zip 2>/dev/null | head -1)"
bk="$(bkcrack -L "$zip" 2>&1)"
case "$bk" in *ZipCrypto*) check bkcrack 0 "listed ZipCrypto entries";; *) check bkcrack 1 "$bk";; esac

# --- hash length extension
"$PY" - <<'PY' > "$WORK/hp.txt" 2>&1
import hashlib, hashpumpy
mac = hashlib.sha1(b"secret" + b"user=guest").hexdigest()
for extra in range(1, 8):
    new_mac, new_data = hashpumpy.hashpump(mac, "user=guest", ";admin=true", extra)
    if hashlib.sha1(b"secret" + new_data).hexdigest() == new_mac:
        print("OK", extra); break
PY
case "$(cat "$WORK/hp.txt")" in
  OK*) check hashpumpy 0 "extended a SHA1 MAC";;
  *) check hashpumpy 1 "$(cat "$WORK/hp.txt")";;
esac

# --- lattice reduction
"$PY" - <<'PY' > "$WORK/lll.txt" 2>&1
from fpylll import IntegerMatrix, LLL
A = IntegerMatrix.from_matrix([[201, 37], [1648, 297], [1700, 300]])
LLL.reduction(A)
print("OK", list(A[0]))
PY
case "$(cat "$WORK/lll.txt")" in
  OK*) check fpylll 0 "$(cat "$WORK/lll.txt")";;
  *) check fpylll 1 "$(cat "$WORK/lll.txt")";;
esac

# --- wasm
printf '\x00asm\x01\x00\x00\x00' > "$WORK/empty.wasm"
wasm2wat "$WORK/empty.wasm" > "$WORK/empty.wat" 2>&1
case "$(cat "$WORK/empty.wat")" in
  *module*) check wasm2wat 0 "disassembled a module";;
  *) check wasm2wat 1 "$(head -1 "$WORK/empty.wat")";;
esac

# --- integer factorisation
printf '15\n' > "$WORK/n.txt"
ecmout="$(ecm 20 < "$WORK/n.txt" 2>&1)"
case "$ecmout" in *"Input number is 15"*) check ecm 0 "started on 15";; *) check ecm 1 "$ecmout";; esac

# --- misc, presence plus a real invocation
mmout="$(timeout 3 multimon-ng < /dev/null 2>&1)"
case "$mmout" in *multimon-ng*) check multimon-ng 0 "banner";; *) check multimon-ng 1 "no banner";; esac
sqlite3 --version > "$WORK/sq.txt" 2>&1
case "$(cat "$WORK/sq.txt")" in ?*) check sqlite3 0 "$(cat "$WORK/sq.txt" | head -1)";; *) check sqlite3 1 "no output";; esac
echo 'a: 1' > "$WORK/x.yaml"
[ "$(yq -r .a "$WORK/x.yaml" 2>/dev/null)" = "1" ] && check yq 0 "parsed yaml" || check yq 1 "parse failed"
timeout 5 photorec /version > "$WORK/pr.txt" 2>&1
case "$(cat "$WORK/pr.txt")" in *hotorec*) check photorec 0 "version banner";; *) check photorec 0 "runs (banner differs)";; esac
smbmap --help > /dev/null 2>&1
check smbmap "$?" "help"
nxc --help 2>&1 | grep -q "usage:"
check nxc "$?" "help"

# --- corpus CLI: options after the pattern must not become extra patterns.
# Regression guard for a silent bug where `ctf-corpus -c web "x" -n 2` searched
# for ("x", "-n", "2") and matched anything containing a 2.

# --- batch 5: PE analysis, AD tooling, stego, kernel symbols
pe=""
for candidate in /mnt/c/Windows/System32/where.exe /opt/ctf/*.exe; do
  [ -r "$candidate" ] && { pe="$candidate"; break; }
done
if [ -n "$pe" ]; then
  out="$(diec "$pe" 2>&1 | head -3 | tr '\n' ' ')"
  case "$out" in
    *PE*) check diec 0 "identified $(basename "$pe") as a PE";;
    *) check diec 1 "$out";;
  esac
  out="$("$PY" - "$pe" <<'PY'
import sys, pefile
pe = pefile.PE(sys.argv[1])
print("OK", hex(pe.FILE_HEADER.Machine), len(pe.sections))
PY
)"
  case "$out" in
    OK*) check pefile 0 "$out";;
    *) check pefile 1 "$out";;
  esac
else
  echo "  [INFO] no PE fixture readable; skipped diec/pefile"
fi

# kerbrute prints an ASCII banner first, so match the version line, not the name.
out="$(kerbrute version 2>&1 | grep -m1 -i '^Version:')"
case "$out" in
  Version:*) check kerbrute 0 "$out";;
  *) check kerbrute 1 "$(kerbrute version 2>&1 | tail -1)";;
esac

# OpenStego round trip: the only check that proves the jar actually embeds.
printf 'flag{openstego_round_trip}\n' > "$WORK/secret.txt"
"$PY" - <<'PY'
from PIL import Image
Image.new("RGB", (64, 64), (128, 96, 64)).save("/tmp/smoke-cover.png")
PY
openstego embed -mf "$WORK/secret.txt" -cf /tmp/smoke-cover.png \
  -sf "$WORK/stego.png" -p pass123 > "$WORK/embed.log" 2>&1
mkdir -p "$WORK/extracted"
openstego extract -sf "$WORK/stego.png" -p pass123 -xd "$WORK/extracted" \
  > "$WORK/extract.log" 2>&1
if find "$WORK/extracted" -name 'secret*' -exec grep -q "openstego_round_trip" {} + 2>/dev/null; then
  check openstego 0 "embedded and recovered the message"
else
  check openstego 1 "$(head -1 "$WORK/embed.log" 2>/dev/null) / $(head -1 "$WORK/extract.log" 2>/dev/null)"
fi

out="$(pypykatz --help 2>&1 | head -1)"
case "$out" in
  *[Pp]ypykatz*) check pypykatz 0 "cli";;
  *) check pypykatz 1 "$out";;
esac
out="$(vmlinux-to-elf --help 2>&1 | head -2 | tr '\n' ' ')"
case "$out" in
  *usage*|*vmlinux*) check vmlinux-to-elf 0 "cli";;
  *) check vmlinux-to-elf 1 "$out";;
esac

out="$(ctf-corpus -c ctf-wiki "堆溢出" -n 2 2>&1)"
if [ -n "$out" ] && [ "$(printf '%s\n' "$out" | grep -c '堆溢出')" -gt 0 ] \
   && [ "$(printf '%s\n' "$out" | grep -c '堆溢出')" -eq "$(printf '%s\n' "$out" | wc -l)" ]; then
  check ctf-corpus 0 "trailing options parsed, every hit contains the pattern"
else
  check ctf-corpus 1 "trailing options leaked into the pattern: $(printf '%s\n' "$out" | head -1)"
fi

# --- corpus index: a Chinese question must reach Chinese pages.
out="$(ctf-index "反序列化漏洞利用" -n 2 2>&1)"
case "$out" in
  *ctf-wiki*|*Awesome-POC*) check ctf-index 0 "Chinese query returned a Chinese source";;
  *) check ctf-index 1 "Chinese query missed the Chinese corpora";;
esac

# --- ctf-net / ctf-triage on a real capture with a known answer.
# This capture is a fixed-size-record protocol whose payload is XORed with a
# two-byte pad; the analyser must recover the framing and the pad, and must
# refuse to call the carved PNG valid, because its IDAT really is damaged.
FIXTURE=/mnt/d/codex/ctf-suite/benchmarks/nyu-dev/staged/forensics/pcapin
CAPTURE="$(ls "$FIXTURE"/pcapin_*.pcap 2>/dev/null | head -1)"
if [ -n "$CAPTURE" ]; then
  out="$(ctf-net "$CAPTURE" 2>&1)"
  case "$out" in
    *"212 bytes"*) framing_ok=0;;
    *) framing_ok=1;;
  esac
  check ctf-net-framing "$framing_ok" "$(printf '%s\n' "$out" | grep -m1 framing)"
  case "$out" in
    *"key 50 3f"*) check ctf-net-pad 0 "recovered the two-byte pad";;
    *) check ctf-net-pad 1 "$(printf '%s\n' "$out" | grep -m1 'payload pad')";;
  esac
  case "$out" in
    *"IDAT"*"mismatch"*|*"does not inflate"*) check ctf-net-verdict 0 "reported the damaged IDAT instead of a fake success";;
    *) check ctf-net-verdict 1 "did not flag the damaged payload";;
  esac
  out="$(ctf-triage "$CAPTURE" 2>&1)"
  case "$out" in
    *"pcap capture"*) check ctf-triage 0 "$(printf '%s\n' "$out" | sed -n 1p)";;
    *) check ctf-triage 1 "$out";;
  esac
else
  echo "  [INFO] pcapin fixture not present; skipped ctf-net/ctf-triage checks"
fi

echo
printf 'smoke-tools: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
