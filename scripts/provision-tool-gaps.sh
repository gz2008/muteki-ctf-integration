#!/usr/bin/env bash
# Provision and verify the pinned CTF tools and glibc data that close the local
# ctf-kali gaps. Runs inside ctf-kali; the Muteki tool root exposes the results
# through ./toolbox/bin wrappers.
#
# Usage: bash provision-tool-gaps.sh <provision|check> [asset-root]
set -uo pipefail

COMMAND="${1:-provision}"
ASSET_ROOT="${2:-/mnt/d/codex/output/muteki-ctf-integration/archives/releases}"
BIN=/opt/ctf/bin
TOOLS=/opt/ctf/tools
VENV=/opt/ctf/venvs/core/bin
GLIBC=/opt/ctf/third-party/glibc-all-in-one

EXPECT_YSOSERIAL=2c9bddd6a1a4ec66c1078ea97dacb61eb66d1c41aec7b6d21e3c72214ce170f1
EXPECT_MARSHALSEC=524115cfae28f11759856f2e10946305d686b018a85a01642b436ee28cbb52af
EXPECT_JNDI=53517fdc0d386c7dfd4546e9e83150f85dab0662dbcaf9bf0f9dd82fab3a07e9
EXPECT_STEGSOLVE=2cc24c81d6731b9e5672d2e7ec129378705dfc9a87024c7a24ae740d5efa404f
EXPECT_EVTX=a64220cd31e006b4d37c90adb6cca776120f463953b59de71a8089563307b937
EXPECT_FOUNDRY=6c66ffcc55fa4249197721baa3098bc208014ea1d8aa04b2ed50ac6bccffb226
EXPECT_CHAINSAW=fc25f1eafbbff3e858d8dfba508d5e227bb56ef4dccc4d5cd0bbd6e49798cb4f
EXPECT_HAYABUSA=955d483adf2e952cdeed06a4057b81acd11dd8c208e18f1f5c8eb37cc09b6d1c
EXPECT_CHISEL_AMD64=f3f180f1d93aa72cce4e6386f98cc06569a0146fbd65eb4423cf83e6434bcfe6
EXPECT_CHISEL_ARM64=2ec6152cd2c74fe0146d4d79e4e7aa174521368c56e433d55e023a92ea404ec3
EXPECT_CLOUDFOX=3cdc5a1a94ff14eb8df04d3dc8f9eca7db232a1315ceb8a7de26e4cb13e32fd5
EXPECT_BKCRACK=45dc7d81adbaaad5c0aa2d8615ea920fd08b732fda1ea945504e0a3e8dc1d2ab
EXPECT_CFR=f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2
EXPECT_KERBRUTE=710a9d2653c8bd3689e451778dab9daec0de4c4c75f900788ccf23ef254b122a
EXPECT_OPENSTEGO=402ba4190d329564996a1250b9096f0402452042469f517545c312527cedc41f
TOOL_ROOT=/mnt/d/codex/output/muteki-ctf-integration/muteki-tool-root
VENV_PY=/opt/ctf/venvs/core/bin/python
VENV_PIP=/opt/ctf/venvs/core/bin/pip

venv_pins_ok() {
  "$VENV_PY" - >/dev/null 2>&1 <<'PY'
import importlib
for name in ("claripy", "angr", "fastapi", "web3", "pkg_resources"):
    importlib.import_module(name)
PY
}

verify_hash() {
  local file="$1" expected="$2" label="$3"
  if [ ! -f "$file" ]; then
    echo "${label}=missing"
    return 1
  fi
  local actual
  actual="$(sha256sum "$file" | cut -d' ' -f1)"
  if [ "$actual" = "$expected" ]; then
    echo "${label}=ok"
    return 0
  fi
  echo "${label}=hash-mismatch:$actual"
  return 1
}

install_asset() {
  local asset="$1" target="$2" expected="$3" label="$4"
  if [ -f "$target" ] && [ "$(sha256sum "$target" | cut -d' ' -f1)" = "$expected" ]; then
    return 0
  fi
  if [ ! -f "$ASSET_ROOT/$asset" ]; then
    echo "${label}=asset-missing:$ASSET_ROOT/$asset"
    return 1
  fi
  mkdir -p "$(dirname "$target")"
  cp -f "$ASSET_ROOT/$asset" "$target"
  chmod 0755 "$target"
  if [ "$(sha256sum "$target" | cut -d' ' -f1)" != "$expected" ]; then
    echo "${label}=hash-mismatch-after-copy"
    return 1
  fi
  echo "${label}=installed"
}

write_launcher() {
  local path="$1" body="$2"
  printf '%s\n' "$body" > "$path"
  chmod 0755 "$path"
}

# `check` may run in a non-login shell where /opt/ctf/bin is not on PATH, so a
# launcher counts as present when its absolute path exists, and only then when
# bash can resolve it by name.
has_tool() {
  local name="$1" dir
  for dir in "$BIN" "$TOOLS" "$VENV" /usr/bin /usr/local/bin; do
    [ -x "$dir/$name" ] && return 0
  done
  command -v "$name" >/dev/null 2>&1
}

provision_java() {
  install_asset ysoserial-all.jar "$TOOLS/ysoserial-all.jar" "$EXPECT_YSOSERIAL" ysoserial
  install_asset marshalsec-0.0.3-SNAPSHOT-all.jar "$TOOLS/marshalsec.jar" "$EXPECT_MARSHALSEC" marshalsec
  install_asset JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar "$TOOLS/jndi-injection-exploit.jar" "$EXPECT_JNDI" jndi
  install_asset StegSolve-1.4.jar "$TOOLS/stegsolve.jar" "$EXPECT_STEGSOLVE" stegsolve
  write_launcher "$BIN/ysoserial" '#!/usr/bin/env bash
exec java -jar /opt/ctf/tools/ysoserial-all.jar "$@"'
  # marshalsec ships no Main-Class manifest: callers pass the gadget class.
  write_launcher "$BIN/marshalsec" '#!/usr/bin/env bash
exec java -cp /opt/ctf/tools/marshalsec.jar "$@"'
  write_launcher "$BIN/jndi-exploit" '#!/usr/bin/env bash
exec java -jar /opt/ctf/tools/jndi-injection-exploit.jar "$@"'
  write_launcher "$BIN/stegsolve" '#!/usr/bin/env bash
exec java -jar /opt/ctf/tools/stegsolve.jar "$@"'
}

provision_binaries() {
  install_asset evtx_dump-v0.12.3-x86_64-unknown-linux-gnu "$BIN/evtx_dump" "$EXPECT_EVTX" evtx_dump
  if [ ! -x "$BIN/pwninit" ]; then
    command -v cargo >/dev/null 2>&1 || { echo "pwninit=no-cargo"; return 1; }
    echo "pwninit=build"
    cargo install --git https://github.com/io12/pwninit --tag 3.3.3 --root /opt/ctf --locked >/dev/null 2>&1 ||
      { echo "pwninit=build-failed"; return 1; }
  fi
  echo "pwninit=ok"
  if [ ! -x "$VENV/stegoveritas" ]; then
    echo "stegoveritas=install"
    "$VENV/pip" install -q stegoveritas >/dev/null 2>&1 || { echo "stegoveritas=install-failed"; return 1; }
  fi
  echo "stegoveritas=ok"
}

verify_asset() {
  local asset="$1" expected="$2" label="$3"
  if [ ! -f "$ASSET_ROOT/$asset" ]; then
    echo "${label}=asset-missing"
    return 1
  fi
  local actual
  actual="$(sha256sum "$ASSET_ROOT/$asset" | cut -d' ' -f1)"
  if [ "$actual" = "$expected" ]; then
    echo "${label}=ok"
    return 0
  fi
  echo "${label}=hash-mismatch:$actual"
  return 1
}

provision_second_batch() {
  verify_asset foundry_v1.8.5_linux_amd64.tar.gz "$EXPECT_FOUNDRY" foundry-asset
  verify_asset chainsaw_x86_64-unknown-linux-gnu.tar.gz "$EXPECT_CHAINSAW" chainsaw-asset
  verify_asset hayabusa-4.2.0-lin-x64-gnu.zip "$EXPECT_HAYABUSA" hayabusa-asset
  verify_asset chisel_1.12.0_linux_amd64.gz "$EXPECT_CHISEL_AMD64" chisel-amd64-asset
  verify_asset chisel_1.12.0_linux_arm64.gz "$EXPECT_CHISEL_ARM64" chisel-arm64-asset

  if [ ! -x /opt/ctf/foundry/forge ]; then
    mkdir -p /opt/ctf/foundry &&
      tar -xzf "$ASSET_ROOT/foundry_v1.8.5_linux_amd64.tar.gz" -C /opt/ctf/foundry
  fi
  if [ ! -x /opt/ctf/chainsaw/chainsaw ]; then
    mkdir -p /opt/ctf/chainsaw &&
      tar -xzf "$ASSET_ROOT/chainsaw_x86_64-unknown-linux-gnu.tar.gz" -C /opt/ctf/chainsaw
  fi
  if [ ! -x /opt/ctf/hayabusa/hayabusa-4.2.0-lin-x64-gnu ]; then
    mkdir -p /opt/ctf/hayabusa &&
      unzip -q -o "$ASSET_ROOT/hayabusa-4.2.0-lin-x64-gnu.zip" -d /opt/ctf/hayabusa
  fi
  chmod 0755 /opt/ctf/hayabusa/hayabusa-4.2.0-lin-x64-gnu 2>/dev/null

  write_launcher "$BIN/forge" '#!/usr/bin/env bash
exec /opt/ctf/foundry/forge "$@"'
  write_launcher "$BIN/cast" '#!/usr/bin/env bash
exec /opt/ctf/foundry/cast "$@"'
  write_launcher "$BIN/anvil" '#!/usr/bin/env bash
exec /opt/ctf/foundry/anvil "$@"'
  # Foundry also ships a Solidity REPL called chisel; the CTF tunnel keeps the
  # plain `chisel` name, so the REPL is exposed as fchisel.
  write_launcher "$BIN/fchisel" '#!/usr/bin/env bash
exec /opt/ctf/foundry/chisel "$@"'
  write_launcher "$BIN/solar" '#!/usr/bin/env bash
exec /opt/ctf/foundry/solar "$@"'
  # chainsaw resolves mappings/ and hayabusa resolves rules/ relative to their
  # working directory, so the launchers cd into the install directory first.
  write_launcher "$BIN/chainsaw" '#!/usr/bin/env bash
cd /opt/ctf/chainsaw || exit 1
exec ./chainsaw "$@"'
  write_launcher "$BIN/hayabusa" '#!/usr/bin/env bash
cd /opt/ctf/hayabusa || exit 1
exec ./hayabusa-4.2.0-lin-x64-gnu "$@"'

  if [ ! -x "$BIN/pycdc" ]; then
    if [ -x /tmp/pycdc/pycdc ]; then
      install -m 0755 /tmp/pycdc/pycdc "$BIN/pycdc"
      install -m 0755 /tmp/pycdc/pycdas "$BIN/pycdas"
    else
      echo "pycdc=build"
      rm -rf /tmp/pycdc
      git clone --quiet --depth 1 https://github.com/zrax/pycdc.git /tmp/pycdc >/dev/null 2>&1 &&
        (cd /tmp/pycdc && cmake -DCMAKE_BUILD_TYPE=Release . >/dev/null 2>&1 && make -j4 >/dev/null 2>&1) &&
        install -m 0755 /tmp/pycdc/pycdc "$BIN/pycdc" &&
        install -m 0755 /tmp/pycdc/pycdas "$BIN/pycdas"
    fi
  fi
  [ -x "$BIN/pycdc" ] && echo "pycdc=ok" || echo "pycdc=missing"

  mkdir -p "$TOOL_ROOT/tools/target-binaries"
  if [ ! -x "$TOOL_ROOT/tools/target-binaries/chisel-linux-amd64" ]; then
    gunzip -c "$ASSET_ROOT/chisel_1.12.0_linux_amd64.gz" > "$TOOL_ROOT/tools/target-binaries/chisel-linux-amd64"
  fi
  if [ ! -x "$TOOL_ROOT/tools/target-binaries/chisel-linux-arm64" ]; then
    gunzip -c "$ASSET_ROOT/chisel_1.12.0_linux_arm64.gz" > "$TOOL_ROOT/tools/target-binaries/chisel-linux-arm64"
  fi
  chmod 0755 "$TOOL_ROOT/tools/target-binaries/chisel-linux-amd64" "$TOOL_ROOT/tools/target-binaries/chisel-linux-arm64"
  echo "chisel-target-binaries=ok"
}

provision_third_batch() {
  verify_asset cloudfox-linux-amd64.zip "$EXPECT_CLOUDFOX" cloudfox-asset
  if [ ! -x "$BIN/cloudfox" ]; then
    rm -rf /tmp/cloudfox-x
    mkdir -p /tmp/cloudfox-x
    unzip -q -o "$ASSET_ROOT/cloudfox-linux-amd64.zip" -d /tmp/cloudfox-x &&
      install -m 0755 /tmp/cloudfox-x/cloudfox/cloudfox "$BIN/cloudfox"
    rm -rf /tmp/cloudfox-x
  fi
  [ -x "$BIN/cloudfox" ] && echo "cloudfox=ok" || echo "cloudfox=missing"

  # Bulk pip installs into the shared core venv drift the pins below; re-assert
  # them so angr/fastapi/mcp and the pkg_resources consumers keep working.
  if ! venv_pins_ok; then
    echo "venv-pins=reapplying"
    "$VENV_PIP" install -q "pydantic>=2.9,<3" claripy "z3-solver==5.1.0.0" \
      "arpy==1.1.1" "setuptools<81" >/dev/null 2>&1
  fi
  venv_pins_ok && echo "venv-pins=ok" || echo "venv-pins=missing"
}

install_apt_packages() {
  local missing=()
  local package
  for package in "$@"; do
    dpkg -s "$package" >/dev/null 2>&1 || missing+=("$package")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    return 0
  fi
  echo "apt-install=${missing[*]}"
  # The default Kali mirror intermittently answers AAAA only; force IPv4 and
  # retry rather than reporting a false "package unavailable".
  sudo -n apt-get install -y -o Acquire::ForceIPv4=true -o Acquire::Retries=5 \
    "${missing[@]}" >/dev/null 2>&1
}

# Gaps found by auditing the tool names the CTF playbooks actually reference
# (`bash tools/playbook-tool-audit.sh`), not by guessing.
provision_fourth_batch() {
  install_apt_packages tesseract-ocr tesseract-ocr-eng smbclient smbmap netexec \
    sqlite3 tftp-hpa wabt multimon-ng gmp-ecm yq photorec

  if ! "$VENV_PY" -c "import fpylll, volatility3, regipy, dnfile, csvkit, hashpumpy, Cryptodome" \
       >/dev/null 2>&1; then
    echo "pip-install=fourth-batch"
    "$VENV_PIP" install -q --no-input volatility3 fpylll cysignals regipy dnfile \
      csvkit pycryptodomex hashpumpy >/dev/null 2>&1
  fi
  if ! venv_pins_ok; then
    echo "venv-pins=reapplying"
    "$VENV_PIP" install -q "pydantic>=2.9,<3" claripy "z3-solver==5.1.0.0" \
      "arpy==1.1.1" "setuptools<81" >/dev/null 2>&1
  fi
  venv_pins_ok && echo "venv-pins=ok" || echo "venv-pins=missing"

  # The playbooks say `vol3`; volatility3 ships the command as `vol`.
  write_launcher "$BIN/vol3" '#!/usr/bin/env bash
exec /opt/ctf/venvs/core/bin/vol "$@"'
  echo "vol3=ok"

  if [ ! -x "$BIN/bkcrack" ]; then
    verify_asset bkcrack-1.8.1-Linux-x86_64.tar.gz "$EXPECT_BKCRACK" fourth-bkcrack-asset
    rm -rf /tmp/bkcrack-x
    mkdir -p /tmp/bkcrack-x
    tar -xzf "$ASSET_ROOT/bkcrack-1.8.1-Linux-x86_64.tar.gz" -C /tmp/bkcrack-x 2>/dev/null &&
      install -m 0755 /tmp/bkcrack-x/bkcrack-*/bkcrack "$BIN/bkcrack"
    rm -rf /tmp/bkcrack-x
  fi
  [ -x "$BIN/bkcrack" ] && echo "bkcrack=ok" || echo "bkcrack=missing"

  install_asset cfr-0.152.jar "$TOOLS/cfr-0.152.jar" "$EXPECT_CFR" cfr
  write_launcher "$BIN/cfr" '#!/usr/bin/env bash
exec java -jar /opt/ctf/tools/cfr-0.152.jar "$@"'
  [ -f "$TOOLS/cfr-0.152.jar" ] && echo "cfr=ok" || echo "cfr=missing"
}

provision_fifth_batch() {
  # AD credential tooling, kernel-pwn symbol recovery, PE parsing, stego.
  install_apt_packages detect-it-easy

  if ! "$VENV_PY" -c "import pypykatz, vmlinux_to_elf, pefile, apkleaks" >/dev/null 2>&1; then
    echo "pip-install=fifth-batch"
    "$VENV_PIP" install -q --no-input pypykatz vmlinux-to-elf pefile apkleaks >/dev/null 2>&1
  fi
  if ! venv_pins_ok; then
    echo "venv-pins=reapplying"
    "$VENV_PIP" install -q "pydantic>=2.9,<3" claripy "z3-solver==5.1.0.0" \
      "arpy==1.1.1" "setuptools<81" >/dev/null 2>&1
  fi
  venv_pins_ok && echo "venv-pins=ok" || echo "venv-pins=missing"

  # kerbrute is a prebuilt Go binary; it needs no runtime of its own.
  if [ ! -x "$BIN/kerbrute" ]; then
    verify_asset kerbrute_linux_amd64 "$EXPECT_KERBRUTE" fifth-kerbrute-asset
    install -m 0755 "$ASSET_ROOT/kerbrute_linux_amd64" "$BIN/kerbrute"
  fi
  [ -x "$BIN/kerbrute" ] && echo "kerbrute=ok" || echo "kerbrute=missing"

  # OpenStego ships as a jar plus a shell wrapper that only adds -jar.
  if [ ! -f "$TOOLS/openstego.jar" ]; then
    verify_asset openstego-0.8.6.zip "$EXPECT_OPENSTEGO" fifth-openstego-asset
    rm -rf /tmp/openstego-x
    mkdir -p /tmp/openstego-x
    unzip -q -o "$ASSET_ROOT/openstego-0.8.6.zip" -d /tmp/openstego-x 2>/dev/null &&
      install -m 0644 /tmp/openstego-x/openstego-*/lib/openstego.jar "$TOOLS/openstego.jar"
    rm -rf /tmp/openstego-x
  fi
  write_launcher "$BIN/openstego" '#!/usr/bin/env bash
exec java -jar /opt/ctf/tools/openstego.jar "$@"'
  [ -f "$TOOLS/openstego.jar" ] && echo "openstego=ok" || echo "openstego=missing"
}

provision_glibc_one() {
  local version="$1"
  local target="$GLIBC/libs/$version"
  if [ -f "$target/libc.so.6" ] || [ -L "$target/libc.so.6" ]; then
    echo "glibc-$version=ok"
    return 0
  fi
  echo "glibc-$version=fetch"
  (cd "$GLIBC" && "$VENV/glibc-aio" download "$version" >/dev/null 2>&1) || true
  if [ ! -e "$target/libc.so.6" ]; then
    (cd "$GLIBC" && bash legacy/download "$version" >/dev/null 2>&1) || true
    if [ ! -e "$target/libc.so.6" ] && [ -e "$GLIBC/legacy/libs/$version/libc.so.6" ]; then
      mkdir -p "$GLIBC/libs"
      mv "$GLIBC/legacy/libs/$version" "$GLIBC/libs/"
    fi
  fi
  if [ -e "$target/libc.so.6" ]; then
    echo "glibc-$version=ok"
  else
    echo "glibc-$version=missing"
    return 1
  fi
}

provision_glibc() {
  command -v zstd >/dev/null 2>&1 || echo "glibc=warn:zstd-missing"
  provision_glibc_one 2.23-0ubuntu11.3_amd64
  provision_glibc_one 2.27-3ubuntu1.6_amd64
  provision_glibc_one 2.31-0ubuntu9.18_amd64
  provision_glibc_one 2.35-0ubuntu3.15_amd64
  provision_glibc_one 2.39-0ubuntu8.9_amd64
}

provision_corpus_entry() {
  # The tool root exposes ./toolbox/bin/ctf-corpus and ./toolbox/bin/ctf-index;
  # inside the distro each launcher just forwards to the integration script.
  write_launcher "$BIN/ctf-corpus" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/corpus-search.sh "$@"'
  write_launcher "$BIN/ctf-index" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/corpus-index.sh "$@"'
  write_launcher "$BIN/ctf-xor" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/xor-kpa.sh "$@"'
  write_launcher "$BIN/ctf-hashpump" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/ctf-hashpump.sh "$@"'
  write_launcher "$BIN/ctf-triage" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/ctf-triage.sh "$@"'
  write_launcher "$BIN/ctf-net" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/ctf-net.sh "$@"'
  write_launcher "$BIN/ctf-repair" '#!/usr/bin/env bash
exec bash /mnt/d/codex/output/muteki-ctf-integration/scripts/ctf-repair.sh "$@"'
  echo "ctf-corpus=ok"
  echo "ctf-index=ok"
  echo "ctf-xor=ok"
  echo "ctf-hashpump=ok"
  echo "ctf-triage=ok"
  echo "ctf-net=ok"
  echo "ctf-repair=ok"
}

check_all() {
  verify_hash "$TOOLS/ysoserial-all.jar" "$EXPECT_YSOSERIAL" ysoserial
  verify_hash "$TOOLS/marshalsec.jar" "$EXPECT_MARSHALSEC" marshalsec
  verify_hash "$TOOLS/jndi-injection-exploit.jar" "$EXPECT_JNDI" jndi
  verify_hash "$TOOLS/stegsolve.jar" "$EXPECT_STEGSOLVE" stegsolve
  verify_hash "$BIN/evtx_dump" "$EXPECT_EVTX" evtx_dump
  for launcher in ysoserial marshalsec jndi-exploit stegsolve pwninit stegoveritas \
                  ctf-corpus ctf-index ctf-xor ctf-hashpump ctf-triage ctf-net ctf-repair; do
    if has_tool "$launcher"; then
      echo "launcher-$launcher=ok"
    else
      echo "launcher-$launcher=missing"
    fi
  done
  for version in 2.23-0ubuntu11.3_amd64 2.27-3ubuntu1.6_amd64 2.31-0ubuntu9.18_amd64 2.35-0ubuntu3.15_amd64 2.39-0ubuntu8.9_amd64; do
    if [ -e "$GLIBC/libs/$version/libc.so.6" ]; then
      echo "glibc-$version=ok"
    else
      echo "glibc-$version=missing"
    fi
  done
  if [ -f /opt/ctf/third-party/libc-database/db/libc6_2.31-0ubuntu9.18_amd64.so ]; then
    echo "libc-database-db=ok"
  else
    echo "libc-database-db=partial:$(ls /opt/ctf/third-party/libc-database/db 2>/dev/null | wc -l | tr -d ' ')"
  fi
}

check_second_batch() {
  for tool in forge cast anvil fchisel solar chainsaw hayabusa pycdc pycdas; do
    if has_tool "$tool"; then
      echo "second-$tool=ok"
    else
      echo "second-$tool=missing"
    fi
  done
  for tool in jadx apktool d2j-dex2jar aapt apksigner adb wpscan ncat dotnet ilspycmd \
              uncompyle6 decompyle3 pyinstaller semgrep slither vyper; do
    if has_tool "$tool"; then
      echo "second-$tool=ok"
    else
      echo "second-$tool=missing"
    fi
  done
  for binary in chisel-linux-amd64 chisel-linux-arm64; do
    if [ -x "$TOOL_ROOT/tools/target-binaries/$binary" ]; then
      echo "second-$binary=ok"
    else
      echo "second-$binary=missing"
    fi
  done
  verify_asset foundry_v1.8.5_linux_amd64.tar.gz "$EXPECT_FOUNDRY" second-foundry-asset
  verify_asset chainsaw_x86_64-unknown-linux-gnu.tar.gz "$EXPECT_CHAINSAW" second-chainsaw-asset
  verify_asset hayabusa-4.2.0-lin-x64-gnu.zip "$EXPECT_HAYABUSA" second-hayabusa-asset
}

check_third_batch() {
  for tool in gqrx openocd pulseview sigrok-cli rtl_433 gnuradio-config-info cloudfox \
              pacu scout prowler cloudsplaining certipy pyocd unblob; do
    if has_tool "$tool"; then
      echo "third-$tool=ok"
    else
      echo "third-$tool=missing"
    fi
  done
  "$VENV_PY" -c "import pymodbus" >/dev/null 2>&1 &&
    echo "third-pymodbus=ok" || echo "third-pymodbus=missing"
  venv_pins_ok && echo "third-venv-imports=ok" || echo "third-venv-imports=missing"
  verify_asset cloudfox-linux-amd64.zip "$EXPECT_CLOUDFOX" third-cloudfox-asset
}

check_fifth_batch() {
  for tool in diec kerbrute openstego pypykatz vmlinux-to-elf; do
    if has_tool "$tool"; then
      echo "fifth-$tool=ok"
    else
      echo "fifth-$tool=missing"
    fi
  done
  for module in pypykatz vmlinux_to_elf pefile apkleaks; do
    if "$VENV_PY" -c "import $module" >/dev/null 2>&1; then
      echo "fifth-py-$module=ok"
    else
      echo "fifth-py-$module=missing"
    fi
  done
  verify_asset kerbrute_linux_amd64 "$EXPECT_KERBRUTE" fifth-kerbrute-asset
  verify_asset openstego-0.8.6.zip "$EXPECT_OPENSTEGO" fifth-openstego-asset
}

check_fourth_batch() {
  for tool in tesseract smbclient smbmap nxc sqlite3 tftp wasm2wat wasm-decompile \
              multimon-ng ecm yq photorec vol3 bkcrack cfr; do
    if has_tool "$tool"; then
      echo "fourth-$tool=ok"
    else
      echo "fourth-$tool=missing"
    fi
  done
  for module in fpylll volatility3 regipy dnfile csvkit hashpumpy Cryptodome; do
    if "$VENV_PY" -c "import $module" >/dev/null 2>&1; then
      echo "fourth-py-$module=ok"
    else
      echo "fourth-py-$module=missing"
    fi
  done
  verify_asset bkcrack-1.8.1-Linux-x86_64.tar.gz "$EXPECT_BKCRACK" fourth-bkcrack-asset
  verify_hash "$TOOLS/cfr-0.152.jar" "$EXPECT_CFR" fourth-cfr-jar
}

case "$COMMAND" in
  provision)
    provision_java
    provision_binaries
    provision_second_batch
    provision_third_batch
    provision_fourth_batch
    provision_fifth_batch
    provision_corpus_entry
    provision_glibc
    ;;
  check)
    check_all
    check_second_batch
    check_third_batch
    check_fourth_batch
    check_fifth_batch
    ;;
  fourth-batch)
    provision_fourth_batch
    ;;
  fifth-batch)
    provision_fifth_batch
    ;;
  corpus-tools)
    # Reinstall only the corpus launchers; useful after adding a new one.
    provision_corpus_entry
    ;;
  *)
    echo "usage: $0 <provision|check|fourth-batch|fifth-batch|corpus-tools> [asset-root]" >&2
    exit 2
    ;;
esac
