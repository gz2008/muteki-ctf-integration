"""One command that replaces the first ten tool calls of a challenge.

Every CTF Step currently starts with the same inventory: file types, entropy,
strings of interest, embedded objects, protections, archive contents. Done by
hand that is five to ten tool round-trips before any progress is made, and each
round-trip costs time whether a human or an agent is driving.

This performs the whole inventory deterministically and prints the next
commands worth running for each detected type. It never guesses: everything it
reports is read from the bytes, and a check it cannot run is reported as
unavailable instead of assumed.

Usage:
  ctf-triage.py [PATH ...]            # files, or every file in a directory
  ctf-triage.py --json [PATH ...]     # machine-readable
  ctf-triage.py --recursive DIR
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import re
import struct
import subprocess
import sys
from pathlib import Path

# See ctf-net.py: a Windows console is not UTF-8 and a stray non-ASCII byte in a
# filename or extracted string would otherwise abort the whole report.
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ordered longest-first so "PK\x03\x04" wins over any shorter prefix.
SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("PNG image", b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", b"\xff\xd8\xff"),
    ("GIF image", b"GIF89a"),
    ("GIF image", b"GIF87a"),
    ("BMP image", b"BM"),
    ("WebP image", b"RIFF"),
    ("PDF document", b"%PDF-"),
    ("ZIP archive", b"PK\x03\x04"),
    ("Java class", b"\xca\xfe\xba\xbe"),
    ("gzip stream", b"\x1f\x8b\x08"),
    ("bzip2 stream", b"BZh"),
    ("xz stream", b"\xfd7zXZ\x00"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
    ("RAR archive", b"Rar!\x1a\x07"),
    ("POSIX tar", b"ustar"),
    ("SQLite database", b"SQLite format 3\x00"),
    ("pcap capture", b"\xd4\xc3\xb2\xa1"),
    ("pcap capture", b"\xa1\xb2\xc3\xd4"),
    ("pcapng capture", b"\x0a\x0d\x0d\x0a"),
    ("ELF binary", b"\x7fELF"),
    ("PE executable", b"MZ"),
    ("Mach-O binary", b"\xfe\xed\xfa\xce"),
    ("Mach-O binary", b"\xcf\xfa\xed\xfe"),
    ("WebAssembly", b"\x00asm"),
    ("Windows registry hive", b"regf"),
    ("Windows event log", b"ElfFile\x00"),
    ("RIFF audio", b"RIFF"),
    ("Ogg stream", b"OggS"),
    ("FLAC audio", b"fLaC"),
    ("ID3 audio", b"ID3"),
    ("ISO image", b"CD001"),
    ("VMDK image", b"KDMV"),
    ("QCOW image", b"QFI\xfb"),
    ("LUKS container", b"LUKS\xba\xbe"),
)

INTEREST = re.compile(
    rb"(?i)(flag\{[^}\r\n]{1,200}\}|ctf\{[^}\r\n]{1,200}\}|key\{[^}\r\n]{1,200}\}"
    rb"|pass(word)?[\"'=:\s]{1,3}[^\s\"']{3,40}"
    rb"|secret[\"'=:\s]{1,3}[^\s\"']{3,40}"
    rb"|token[\"'=:\s]{1,3}[A-Za-z0-9_\-]{8,60}"
    rb"|https?://[^\s\"'<>]{8,120})"
)
PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")


def entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = collections.Counter(blob)
    size = len(blob)
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def identify(data: bytes) -> tuple[str, str]:
    for name, magic in SIGNATURES:
        if data.startswith(magic):
            return name, "magic"
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / max(len(data), 1)
    if printable > 0.9:
        head = data[:4096].lstrip()
        if head[:1] in (b"{", b"["):
            try:
                json.loads(data[:65536].decode("utf-8", "ignore"))
                return "JSON text", "parsed"
            except Exception:
                pass
        if head[:1] == b"<":
            return ("XML/HTML text", "printable")
        return "text", "printable"
    return "unknown binary", "no magic"


def embedded(data: bytes, limit: int = 6) -> list[tuple[str, int]]:
    found = []
    for name, magic in SIGNATURES:
        if len(magic) < 4:
            continue
        offset = data.find(magic, 1)
        if 0 < offset:
            found.append((name, offset))
    found.sort(key=lambda item: item[1])
    return found[:limit]


def interesting_strings(data: bytes, limit: int = 8) -> list[str]:
    seen: list[str] = []
    for match in INTEREST.finditer(data):
        try:
            text = match.group(0).decode("utf-8", "replace")
        except Exception:
            continue
        if text not in seen:
            seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def run(command: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    return (result.stdout or result.stderr or "").strip()


def elf_facts(path: Path, data: bytes) -> list[str]:
    facts = []
    bits = "64-bit" if data[4] == 2 else "32-bit"
    endian = "little" if data[5] == 1 else "big"
    kind = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}.get(
        struct.unpack_from("<H", data, 16)[0], "?")
    facts.append(f"{bits} {endian} {kind}")
    checksec = run(["checksec", "--file", str(path)])
    for line in checksec.splitlines():
        line = line.strip()
        if line and ":" in line and line not in facts:
            facts.append(line)
    return facts[:8]


def pe_facts(data: bytes) -> list[str]:
    try:
        import pefile
    except ImportError:
        return ["pefile not installed"]
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as error:
        return [f"pefile could not parse it: {error}"]
    machine = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0xAA64: "arm64"}.get(
        pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    return [f"{machine}, {len(pe.sections)} sections",
            f"compile timestamp {pe.FILE_HEADER.TimeDateStamp}"]


def image_facts(data: bytes) -> list[str]:
    try:
        from io import BytesIO
        from PIL import Image
        image = Image.open(BytesIO(data))
        return [f"{image.format} {image.size[0]}x{image.size[1]} {image.mode}"]
    except Exception as error:
        return [f"not a readable image: {error}"]


def archive_listing(path: Path) -> list[str]:
    import tarfile
    import zipfile
    entries: list[str] = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist()[:12]:
                    entries.append(f"{info.filename} ({info.file_size} bytes, "
                                   f"{'encrypted' if info.flag_bits & 0x1 else 'plain'})")
                    if len(entries) >= 12:
                        break
            return entries
    except Exception:
        pass
    try:
        with tarfile.open(path) as archive:
            for member in archive.getmembers()[:12]:
                entries.append(f"{member.name} ({member.size} bytes)")
    except Exception:
        pass
    return entries


def pcap_facts(path: Path) -> list[str]:
    facts = []
    output = run(["capinfos", "-c", "-u", str(path)], timeout=30)
    for line in output.splitlines():
        if ":" in line and not line.lower().startswith("file name"):
            facts.append(line.strip())
    return facts[:4]


def suggestions(kind: str, path: str) -> list[str]:
    table = {
        "PNG image": [f"zsteg -a {path}", f"stegseek {path} /usr/share/wordlists/rockyou.txt",
                      f"tesseract {path} -", f"magick {path} -resize 400% -colorspace Gray -threshold 50% /tmp/big.png"],
        "JPEG image": [f"exiftool {path}", f"stegseek {path} /usr/share/wordlists/rockyou.txt",
                       "openstego extract -sf <file> -p <password> -xd out"],
        "ZIP archive": [f"unzip -l {path}", f"zip2john {path} > z.hash && john z.hash",
                        f"bkcrack -C {path} -c <known-file> -p plain.bin"],
        "ELF binary": ["checksec --file <file>", "strings -a -n 6 <file> | head -40",
                       "r2 -A <file> | gdb <file>"],
        "PE executable": ["diec <file>", "pefile/peframe inspection", "ilspycmd (if .NET)",
                          "dnfile / pycdc for packed Python"],
        "pcap capture": ["ctf-net <file> --out carved/   (frames, pads, carving)",
                         "tshark -r <file> -q -z conv,tcp"],
        "pcapng capture": ["ctf-net <file> --out carved/"],
        "SQLite database": ["sqlite3 <file> '.tables' \"select * from <table>;\""],
        "PDF document": ["pdfimages -all <file> out", "pdftotext <file> -",
                         "qpdf --qdf --object-streams=disable <file> out.pdf"],
        "Java class": ["cfr <file>", "jadx <file>"],
        "WebAssembly": ["wasm2wat <file> -o out.wat", "wasm-decompile <file> -o out.dcmp"],
        "Windows registry hive": ["regipy-dump -t <hive>", "pypykatz registry --system SYSTEM --sam SAM"],
        "text": ["base64 -d / CyberChef magic on a copy", "rg -o 'flag\\{.*?\\}' <file>"],
        "unknown binary": ["binwalk -eM <file>", "entropy/xdd on a copy", "foremost -i <file> -o carved"],
    }
    return table.get(kind, []) + ["ctf-corpus -c <category> \"<technique>\"",
                                  "ctf-index \"<what the challenge asks for>\""]


def triage(path: Path, report: dict) -> None:
    size = path.stat().st_size
    data = path.read_bytes()[:8 * 1024 * 1024]
    kind, how = identify(data)
    report["file"] = str(path)
    report["size"] = size
    report["kind"] = kind
    report["entropy"] = round(entropy(data[:2 * 1024 * 1024]), 2)
    report["entropy_note"] = ("packed or encrypted" if report["entropy"] > 7.4
                              else "structured or compressed" if report["entropy"] > 6
                              else "low (text, code, or plain data)")
    report["facts"] = []
    if kind == "ELF binary":
        report["facts"] += elf_facts(path, data)
    elif kind == "PE executable":
        report["facts"] += pe_facts(data)
    elif "image" in kind:
        report["facts"] += image_facts(data)
    elif kind in ("ZIP archive", "POSIX tar"):
        report["facts"] += archive_listing(path)
    elif "pcap" in kind:
        report["facts"] += pcap_facts(path)
    report["embedded"] = [f"{name} at 0x{offset:x}" for name, offset in embedded(data)]
    report["interesting"] = interesting_strings(data)
    report["suggestions"] = suggestions(kind, path.name)
    report["note"] = f"identified by {how}" + ("" if size <= len(data) else
                                               f"; only the first {len(data)} bytes were read")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", default=["."])
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--max-files", type=int, default=40)
    args = parser.parse_args()

    targets: list[Path] = []
    for raw in args.paths:
        path = Path(raw)
        if path.is_dir():
            pattern = "**/*" if args.recursive else "*"
            targets += sorted(item for item in path.glob(pattern) if item.is_file())
        elif path.is_file():
            targets.append(path)
        else:
            print(f"skipping missing path: {path}", file=sys.stderr)
    targets = targets[:args.max_files]
    if not targets:
        print("no files to triage", file=sys.stderr)
        return 2

    reports = []
    for path in targets:
        report: dict = {}
        try:
            triage(path, report)
        except Exception as error:
            report = {"file": str(path), "error": str(error)}
        reports.append(report)

    if args.json:
        print(json.dumps(reports, indent=2, ensure_ascii=False))
        return 0

    for report in reports:
        if "error" in report:
            print(f"== {report['file']}: unreadable ({report['error']})")
            continue
        print(f"== {Path(report['file']).name}  {report['size']} bytes  {report['kind']}")
        print(f"   entropy {report['entropy']} bits/byte - {report['entropy_note']}"
              f"   ({report['note']})")
        for fact in report["facts"][:8]:
            print(f"   | {fact}")
        if report["embedded"]:
            print(f"   embedded: {', '.join(report['embedded'])}")
        if report["interesting"]:
            print("   strings of interest:")
            for text in report["interesting"]:
                print(f"     {text[:110]}")
        print("   next:")
        for line in report["suggestions"]:
            print(f"     {line}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
