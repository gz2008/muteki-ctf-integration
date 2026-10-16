"""Repair a file that is damaged by one small local error.

The hard part after the transport is decoded is often a single wrong byte or a
one-byte shift inside a compressed stream. Correcting it by hand is guesswork
spread over many attempts; the format's own checksum turns it into a search that
either succeeds or provably does not.

Strategy, cheapest first:
  1. single-byte substitution inside a bounded window,
  2. insert one byte,
  3. delete one byte.
Every candidate is judged only by the format's checksum: a full zlib inflate for
PNG/IDAT, or the chunk CRCs after a successful inflate. A candidate that merely
looks plausible is not accepted.

Usage:
  ctf-repair.py DAMAGED.png --format png --write fixed.png
  ctf-repair.py DAMAGED.bin --format raw-zlib --window 0:2048
"""
from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def inflate_fully(blob: bytes) -> bytes | None:
    try:
        return zlib.decompress(blob)
    except zlib.error:
        return None


def first_failure_offset(compressed: bytes) -> int:
    """Where the deflate stream first refuses to decode.

    The damaged byte is at or just before that point, which turns a search over
    the whole stream into a search over a window - the difference between
    minutes and seconds.
    """
    decompressor = zlib.decompressobj()
    good = 0
    for index in range(len(compressed)):
        try:
            decompressor.decompress(compressed[index:index + 1])
        except zlib.error:
            return max(0, good - 2)
        good = index
    return max(0, len(compressed) - 1)


def png_idat(blob: bytes) -> tuple[int, int, bytes] | None:
    """Return (start, end, data) of the concatenated IDAT payload."""
    if not blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    offset, start, end, data = 8, None, None, bytearray()
    while offset + 8 <= len(blob):
        length = struct.unpack_from(">I", blob, offset)[0]
        kind = blob[offset + 4:offset + 8]
        if offset + 12 + length > len(blob):
            break
        if kind == b"IDAT":
            if start is None:
                start = offset + 8
            end = offset + 8 + length
            data += blob[offset + 8:offset + 8 + length]
        elif kind == b"IEND":
            break
        offset += 12 + length
    if start is None:
        return None
    return start, end, bytes(data)


def png_valid(blob: bytes) -> tuple[bool, str]:
    info = png_idat(blob)
    if info is None:
        return False, "no IDAT"
    _, _, idat = info
    inflated = inflate_fully(idat)
    if inflated is None:
        return False, "IDAT still does not inflate"
    # Re-check every chunk CRC on the rebuilt file, so a repair that only made
    # inflate succeed but left another chunk inconsistent is not accepted.
    offset = 8
    while offset + 8 <= len(blob):
        length = struct.unpack_from(">I", blob, offset)[0]
        kind = blob[offset + 4:offset + 8]
        if offset + 12 + length > len(blob):
            return False, f"truncated at {kind!r}"
        chunk = blob[offset + 8:offset + 8 + length]
        stored = struct.unpack_from(">I", blob, offset + 8 + length)[0]
        if stored != (zlib.crc32(kind + chunk) & 0xFFFFFFFF):
            return False, f"{kind.decode('latin-1')} CRC still wrong at byte {offset}"
        if kind == b"IEND":
            return True, f"all chunk CRCs valid, {len(inflated)} inflated bytes"
        offset += 12 + length
    return False, "no IEND"


def search(blob: bytes, region_start: int, region_end: int, judges: list,
           budget: int) -> tuple[bytes, str] | None:
    """Try substitution, insertion and deletion inside the region."""
    attempts = 0
    for position in range(region_start, min(region_end, len(blob))):
        original = blob[position]
        for candidate in range(256):
            if candidate == original:
                continue
            attempts += 1
            trial = blob[:position] + bytes([candidate]) + blob[position + 1:]
            verdict = judges(trial)
            if verdict:
                return trial, f"byte {position} (0x{original:02x} -> 0x{candidate:02x}): {verdict}"
            if attempts >= budget:
                return None
    for position in range(region_start, min(region_end, len(blob))):
        for value in range(256):
            attempts += 1
            trial = blob[:position] + bytes([value]) + blob[position:]
            verdict = judges(trial)
            if verdict:
                return trial, f"inserted 0x{value:02x} at byte {position}: {verdict}"
        if position + 1 < len(blob):
            attempts += 1
            trial = blob[:position] + blob[position + 1:]
            verdict = judges(trial)
            if verdict:
                removed = blob[position]
                return trial, f"deleted 0x{removed:02x} at byte {position}: {verdict}"
        if attempts >= budget:
            return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--format", choices=("png", "raw-zlib"), default="png")
    parser.add_argument("--window", default="",
                        help="restrict the search to START:END (default: the whole payload)")
    parser.add_argument("--budget", type=int, default=400000,
                        help="maximum candidates to try (default 400000)")
    parser.add_argument("--write", default="", help="write the repaired file here")
    args = parser.parse_args()

    blob = Path(args.path).read_bytes()
    if args.format == "png":
        info = png_idat(blob)
        if info is None:
            print("no IDAT chunk found; is this a PNG?", file=sys.stderr)
            return 2
        start, end, idat = info
        print(f"{args.path}: {len(blob)} bytes, IDAT payload {start}..{end} "
              f"({len(idat)} bytes)")
        if args.window:
            region = tuple(int(part) for part in args.window.split(":"))
        else:
            # A local error makes the stream fail at or just after the bad byte,
            # so start there instead of sweeping 5 KB of valid data.
            failure = first_failure_offset(idat)
            region = (start + max(0, failure - 96), start + failure + 96)
            print(f"first inflate failure at IDAT offset {failure} "
                  f"(stream byte {start + failure}); searching {region[0]}..{region[1]}")

        def judges(trial: bytes):
            ok, note = png_valid(trial)
            return note if ok else None

        print(f"searching {region[0]}..{region[1]} for one wrong byte, insert or delete")
        result = search(blob, region[0], region[1], judges, args.budget)
        if not result:
            print("no single-byte repair makes the file valid")
            print("next: the damage is larger than one byte, or the pad/decoding is "
                  "still wrong - re-run ctf-net and check the pad evidence first")
            return 1
        fixed, description = result
        print(f"repaired: {description}")
    else:
        region = tuple(int(part) for part in args.window.split(":")) if args.window else (0, len(blob))
        print(f"{args.path}: {len(blob)} bytes, raw zlib stream")

        def judges(trial: bytes):
            if trial[region[0]:region[1]] is None:
                return None
            payload = trial[region[0]:region[1]]
            inflated = inflate_fully(payload)
            return f"inflates to {len(inflated)} bytes" if inflated is not None else None

        result = search(blob, region[0], region[1], judges, args.budget)
        if not result:
            print("no single-byte repair inflates the stream")
            return 1
        fixed, description = result
        print(f"repaired: {description}")

    if args.write:
        Path(args.write).write_bytes(fixed)
        print(f"wrote {args.write}")
    else:
        print("(pass --write to save the repaired file)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
