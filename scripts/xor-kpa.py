"""Recover a repeating XOR pad from known plaintext, and verify the result.

Guessing single-byte XOR at a random-looking payload burns time and usually
fails. When any plaintext is known or expected - a file magic at the start of a
field, a directory name list, a fixed header - the pad falls out directly:

    pad[i] = cipher[i] XOR known[i]

The pad is then real only if it reproduces a checksum the format carries (PNG
chunk CRCs, zlib, ZIP CRCs). This tool derives the pad, reports its period,
decrypts the rest, and says whether the result passes a structural check.

Usage:
  xor-kpa.py FILE                     # try the common magics as known plaintext
  xor-kpa.py FILE --known 89504e470d0a1a0a
  xor-kpa.py FILE --known 89504e470d0a1a0a --offset 12 --write out.png
"""
from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

# Plaintext prefixes worth assuming at the start of a field. Two of these can
# share a prefix, so the longest match wins.
MAGICS: tuple[tuple[str, bytes], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("gzip", b"\x1f\x8b\x08"),
    ("zip", b"PK\x03\x04"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("pdf", b"%PDF-"),
    ("elf", b"\x7fELF"),
    ("jpg", b"\xff\xd8\xff\xe0"),
    ("bmp", b"BM"),
    ("tiff-le", b"II*\x00"),
    ("sqlite", b"SQLite format 3\x00"),
    ("zlib", b"\x78\x9c"),
    ("bz2", b"BZh9"),
    ("xz", b"\xfd7zXZ\x00"),
    ("pcapng", b"\x0a\x0d\x0d\x0a"),
)


def derive_pad(cipher: bytes, known: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(cipher, known))


def pad_period(pad: bytes, max_period: int) -> int | None:
    """Smallest period consistent with the known window, or None."""
    for period in range(1, max_period + 1):
        if all(byte == pad[index % period] for index, byte in enumerate(pad)):
            return period
    return None


def apply_pad(blob: bytes, pad: bytes) -> bytes:
    if not pad:
        return blob
    return bytes(byte ^ pad[index % len(pad)] for index, byte in enumerate(blob))


def png_ok(blob: bytes) -> str:
    if not blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return "not png"
    offset, idat, idat_crc_ok = 8, bytearray(), None
    while offset + 8 <= len(blob):
        length = struct.unpack_from(">I", blob, offset)[0]
        kind = blob[offset + 4:offset + 8]
        if offset + 12 + length > len(blob):
            return f"truncated at {kind!r}"
        data = blob[offset + 8:offset + 8 + length]
        stored = struct.unpack_from(">I", blob, offset + 8 + length)[0]
        ok = stored == (zlib.crc32(kind + data) & 0xFFFFFFFF)
        if kind == b"IDAT":
            idat += data
            idat_crc_ok = ok
        elif kind == b"IHDR" and not ok:
            return "IHDR CRC mismatch"
        if kind == b"IEND":
            break
        offset += 12 + length
    if idat_crc_ok is False:
        return "IDAT CRC mismatch"
    if not idat:
        return "no IDAT"
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error as error:
        return f"IDAT inflate: {error}"
    return f"valid png, {len(raw)} inflated bytes"


def structural_check(kind: str, blob: bytes) -> str:
    if kind == "png":
        return png_ok(blob)
    if kind == "gzip":
        try:
            return f"valid gzip, {len(zlib.decompress(blob, 47))} bytes"
        except zlib.error as error:
            return f"gzip: {error}"
    if kind == "zlib":
        try:
            return f"valid zlib, {len(zlib.decompress(blob))} bytes"
        except zlib.error as error:
            return f"zlib: {error}"
    if kind == "zip":
        return "EOCD present" if b"PK\x05\x06" in blob else "no EOCD"
    good = sum(1 for b in blob if 32 <= b < 127 or b in (9, 10, 13))
    return f"printable ratio {good / max(len(blob), 1):.2f}"


def report(label: str, cipher: bytes, known: bytes, offset: int,
           max_period: int, write: str | None) -> bool:
    window = cipher[offset:offset + len(known)]
    if len(window) < len(known):
        print(f"  {label}: file too short for that plaintext")
        return False
    pad = derive_pad(window, known)
    period = pad_period(pad, max_period)
    print(f"  {label}: known={known[:8].hex()}{'...' if len(known) > 8 else ''}"
          f" offset={offset}")
    print(f"    derived pad : {pad.hex(' ')}")
    if period is None:
        print(f"    period      : none within {max_period} bytes "
              f"(pad is longer than the known window)")
        return False
    key = pad[:period]
    body = cipher[offset:]
    plain = apply_pad(body, key)
    # The caller may have supplied plaintext without saying what file it is;
    # identify it from the decrypted magic so the check is the strongest one.
    kind = next((name for name, magic in MAGICS if plain.startswith(magic)), "unknown")
    print(f"    period      : {period}  key={key.hex(' ')}")
    print(f"    check       : {structural_check(kind, plain)}")
    print(f"    preview     : {plain[:48]!r}")
    if write:
        Path(write).write_bytes(plain)
        print(f"    wrote       : {write} ({len(plain)} bytes)")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--known", default="",
                        help="known plaintext as hex (default: try common magics)")
    parser.add_argument("--offset", type=int, default=0,
                        help="where the known plaintext starts in the file")
    parser.add_argument("--max-period", type=int, default=16,
                        help="longest repeating pad to report (default 16)")
    parser.add_argument("--write", default="",
                        help="write the decrypted bytes here (single --known only)")
    args = parser.parse_args()

    cipher = Path(args.path).read_bytes()
    print(f"{args.path}: {len(cipher)} bytes")

    if args.known:
        try:
            known = bytes.fromhex(args.known.replace(" ", ""))
        except ValueError:
            print("--known must be hex", file=sys.stderr)
            return 2
        found = report("known", cipher, known, args.offset, args.max_period, args.write)
        return 0 if found else 1

    # No explicit plaintext: assume each magic in turn and keep the candidates
    # whose decryption actually passes a structural check.
    hits = 0
    for label, magic in MAGICS:
        window = cipher[args.offset:args.offset + len(magic)]
        if len(window) < len(magic):
            continue
        pad = derive_pad(window, magic)
        period = pad_period(pad, args.max_period)
        if period is None:
            continue
        plain = apply_pad(cipher[args.offset:], pad[:period])
        verdict = structural_check(label, plain)
        marker = "OK " if verdict.startswith("valid") or "present" in verdict else "?? "
        hits += verdict.startswith("valid") or "present" in verdict
        print(f"  {marker}{label:8s} key={' '.join(f'{b:02x}' for b in pad[:period])}"
              f"  {verdict}")
    if not hits:
        print("no magic produced a structurally valid result; supply --known with "
              "the plaintext you expect at the start of the field")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
