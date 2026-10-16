"""Turn a capture into structure, without hand-writing a parser first.

`tshark -z follow,tcp,raw` gives bytes; it does not tell you how the
application framed them, whether the payload is obfuscated, or which part of a
carved file is broken. Recovering that by hand is what makes network forensics
slow - a real run spent fifteen minutes on a capture whose whole structure was
"N records of fixed size, XORed with a two-byte repeating pad".

This does the mechanical part:

  1. reassemble each TCP conversation in sequence order (out-of-order and
     retransmitted segments otherwise corrupt the stream silently),
  2. find the application frame: the most frequent repeated 4-byte value with a
     constant spacing is almost always the protocol magic, and the spacing is
     the record size,
  3. try to derive a repeating XOR pad from plaintext the format forces to be
     present (file magics), and only report a pad that is periodic,
  4. validate everything it claims with the format's own checksum (PNG chunk
     CRC, zlib stream, ZIP end-of-central-directory) and say exactly which part
     failed - "the pad is right, the IDAT is damaged at byte N" is an answer.

Usage:
  ctf-net.py CAPTURE.pcap [--out DIR] [--stream N] [--hex BYTES]
"""
from __future__ import annotations

import argparse
import collections
import math
import struct
import sys
import zlib
from pathlib import Path

# Deliberately stdlib-only. The tool has to run wherever the challenge files are
# - including a Windows host whose agent sandbox refuses to start WSL - and a
# missing scapy there would otherwise make the whole analyser unavailable.

# A Windows console is not UTF-8 by default and printing a replacement character
# raises UnicodeEncodeError mid-report, which loses the whole finding.
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def safe(text: bytes | str) -> str:
    """Printable-ASCII rendering of arbitrary bytes, for report lines."""
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    return "".join(char if 32 <= ord(char) < 127 else "." for char in text)

# Plaintext a format forces to be present. Only these can bootstrap a pad.
MAGICS: tuple[tuple[str, bytes], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b\x08"),
    ("pdf", b"%PDF-"),
    ("elf", b"\x7fELF"),
    ("jpeg", b"\xff\xd8\xff"),
    # Two-byte magics are deliberately absent: at 33 candidate offsets a "BM"
    # match is chance, and a chance candidate that ranks first is worse than no
    # candidate at all.
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("rar", b"Rar!\x1a\x07"),
    ("pcapng", b"\x0a\x0d\x0d\x0a"),
    ("sqlite", b"SQLite format 3\x00"),
)


def entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = collections.Counter(blob)
    length = len(blob)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def printable_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    good = sum(1 for byte in blob if 32 <= byte < 127 or byte in (9, 10, 13))
    return good / len(blob)


PCAP_LE = b"\xd4\xc3\xb2\xa1"
PCAP_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG = b"\x0a\x0d\x0d\x0a"


def read_capture(path: str) -> list[dict]:
    """Read pcap or pcapng and return transport segments, without dependencies.

    Only what a CTF capture uses: Ethernet, Linux cooked, raw IP and loopback
    link types, IPv4, IPv6 (no extension headers), TCP and UDP.
    """
    data = Path(path).read_bytes()
    if data[:4] == PCAPNG:
        frames = _read_pcapng(data)
    elif data[:4] in (PCAP_LE, PCAP_BE):
        frames = _read_pcap(data)
    else:
        raise SystemExit(f"not a pcap or pcapng file: {path}")
    segments = []
    for link_type, frame in frames:
        segment = _parse_frame(link_type, frame)
        if segment:
            segments.append(segment)
    return segments


def _read_pcap(data: bytes) -> list[tuple[int, bytes]]:
    endian = "<" if data[:4] == PCAP_LE else ">"
    link_type = struct.unpack_from(f"{endian}I", data, 20)[0]
    if struct.unpack_from(f"{endian}I", data, 0)[0] == 0xA1B2C3D4:
        pass
    frames = []
    offset = 24
    while offset + 16 <= len(data):
        _, _, captured, _ = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if captured > len(data) - offset:
            break
        frames.append((link_type, data[offset:offset + captured]))
        offset += captured
    return frames


def _read_pcapng(data: bytes) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    link_types: dict[int, int] = {}
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8:offset + block_len - 4]
        if block_type == 1 and len(body) >= 8:          # Interface Description
            link_types[struct.unpack_from("<H", body, 0)[0]] = struct.unpack_from("<H", body, 0)[0]
            link_types[len(link_types) - 1] = struct.unpack_from("<H", body, 0)[0]
        elif block_type == 6 and len(body) >= 20:        # Enhanced Packet
            interface = struct.unpack_from("<I", body, 0)[0]
            captured = struct.unpack_from("<I", body, 12)[0]
            payload = body[20:20 + captured]
            frames.append((link_types.get(interface, 1), payload))
        offset += block_len
    return frames


def _parse_frame(link_type: int, frame: bytes) -> dict | None:
    if link_type == 1:                                   # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
            ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4
        if ethertype == 0x0800:
            return _parse_ipv4(frame[offset:])
        if ethertype == 0x86DD:
            return _parse_ipv6(frame[offset:])
        return None
    if link_type in (0, 108):                            # null / loopback
        family = struct.unpack_from("<I", frame, 0)[0] if len(frame) >= 4 else 0
        return _parse_ipv4(frame[4:]) if family == 2 else _parse_ipv6(frame[4:])
    if link_type == 113:                                 # Linux cooked (SLL)
        if len(frame) < 16:
            return None
        protocol = struct.unpack_from(">H", frame, 14)[0]
        if protocol == 0x0800:
            return _parse_ipv4(frame[16:])
        if protocol == 0x86DD:
            return _parse_ipv6(frame[16:])
        return None
    if link_type == 101:                                 # raw IP
        return _parse_ipv4(frame) if frame[:1] == b"\x45" else _parse_ipv6(frame)
    return None


def _parse_ipv4(blob: bytes) -> dict | None:
    if len(blob) < 20:
        return None
    ihl = (blob[0] & 0x0F) * 4
    protocol = blob[9]
    src = ".".join(str(b) for b in blob[12:16])
    dst = ".".join(str(b) for b in blob[16:20])
    return _parse_transport(protocol, src, dst, blob[ihl:])


def _parse_ipv6(blob: bytes) -> dict | None:
    if len(blob) < 40:
        return None
    protocol = blob[6]
    src = ":".join(f"{int.from_bytes(blob[o:o + 2], 'big'):x}" for o in range(8, 24, 2))
    dst = ":".join(f"{int.from_bytes(blob[o:o + 2], 'big'):x}" for o in range(24, 40, 2))
    return _parse_transport(protocol, src, dst, blob[40:])


def _parse_transport(protocol: int, src: str, dst: str, blob: bytes) -> dict | None:
    if protocol == 6 and len(blob) >= 20:                # TCP
        sport, dport, seq = struct.unpack_from(">HHI", blob, 0)
        header = (blob[12] >> 4) * 4
        payload = blob[header:]
        if not payload:
            return None
        return {"src": src, "sport": sport, "dst": dst, "dport": dport,
                "proto": "tcp", "seq": seq, "payload": payload}
    if protocol == 17 and len(blob) >= 8:                # UDP
        sport, dport, length = struct.unpack_from(">HHH", blob, 0)
        payload = blob[8:length if 8 <= length <= len(blob) else len(blob)]
        if not payload:
            return None
        return {"src": src, "sport": sport, "dst": dst, "dport": dport,
                "proto": "udp", "seq": None, "payload": payload}
    return None


def reassemble(segments: list[dict]) -> tuple[dict[tuple, bytes], collections.Counter, int]:
    """Sequence-ordered reassembly per direction.

    Appending segments in capture order is wrong whenever a segment is
    retransmitted or reordered, and the failure is silent: the bytes are there,
    just in the wrong place.
    """
    grouped: dict[tuple, dict[int, bytes]] = collections.defaultdict(dict)
    overlaps: collections.Counter = collections.Counter()
    for index, segment in enumerate(segments):
        key = (segment["src"], segment["sport"], segment["dst"], segment["dport"])
        # UDP carries no sequence, so arrival order is the only ordering there is.
        sequence = segment["seq"] if segment["seq"] is not None else index
        if sequence in grouped[key]:
            overlaps[key] += 1
        grouped[key][sequence] = segment["payload"]
    streams = {key: b"".join(part for _, part in sorted(chunks.items()))
               for key, chunks in grouped.items()}
    return streams, overlaps, len(segments)


def find_framing(blob: bytes, minimum_records: int = 3) -> tuple[int, bytes] | None:
    """Locate a fixed-size record framing: a repeated value at constant spacing."""
    if len(blob) < 32:
        return None
    positions: dict[bytes, list[int]] = collections.defaultdict(list)
    for offset in range(len(blob) - 4):
        positions[blob[offset:offset + 4]].append(offset)
    best = None
    for value, offsets in positions.items():
        if len(offsets) < minimum_records:
            continue
        gaps = [b - a for a, b in zip(offsets, offsets[1:])]
        common, count = collections.Counter(gaps).most_common(1)[0]
        if count < minimum_records - 1 or common < 8:
            continue
        # Only the header magic repeats at a constant stride; a byte pattern
        # that happens to repeat inside data does not produce a stable spacing.
        score = count * common
        if best is None or score > best[0]:
            best = (score, common, value)
    if best is None:
        return None
    return best[1], best[2]


def pad_period(pad: bytes, max_period: int = 8) -> int | None:
    for period in range(1, max_period + 1):
        if all(byte == pad[index % period] for index, byte in enumerate(pad)):
            return period
    return None


def apply_pad(blob: bytes, pad: bytes) -> bytes:
    return bytes(byte ^ pad[index % len(pad)] for index, byte in enumerate(blob))


def png_report(blob: bytes) -> tuple[int, bool, str]:
    """Walk PNG chunks; return (structural score, fully valid, summary).

    The score counts milestones a real PNG reaches, so a genuinely damaged file
    ("magic right, IHDR and bKGD CRCs pass, IDAT broken") still outranks a
    chance magic match somewhere else in the stream.
    """
    if not blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return 0, False, "not a PNG"
    score = 1
    offset, idat, notes, reached_iend = 8, bytearray(), [], False
    while offset + 8 <= len(blob):
        length = struct.unpack_from(">I", blob, offset)[0]
        kind = blob[offset + 4:offset + 8]
        if offset + 12 + length > len(blob):
            notes.append(f"truncated inside {safe(kind)} at byte {offset}")
            break
        data = blob[offset + 8:offset + 8 + length]
        stored = struct.unpack_from(">I", blob, offset + 8 + length)[0]
        if stored != (zlib.crc32(kind + data) & 0xFFFFFFFF):
            notes.append(f"{safe(kind)} CRC mismatch at byte {offset}")
        else:
            score += 1
        if kind == b"IDAT":
            idat += data
        if kind == b"IEND":
            reached_iend = True
            score += 1
            break
        offset += 12 + length
    if not idat:
        return score, False, "; ".join(notes) or "no IDAT chunk"
    try:
        inflated = zlib.decompress(bytes(idat))
    except zlib.error as error:
        return score, False, "; ".join(notes + [f"IDAT does not inflate: {error}"])
    score += 2
    if notes:
        return score, False, "; ".join(notes)
    return score, reached_iend, f"valid PNG, {len(inflated)} inflated bytes"


def validate(kind: str, blob: bytes) -> tuple[int, bool, str]:
    """Return (structural score, fully valid, summary)."""
    if kind == "png":
        return png_report(blob)
    if kind == "zip":
        has_end = b"PK\x05\x06" in blob
        # Local-header counts are not evidence on their own: a repeating filler
        # pattern under a chosen key maps cleanly onto "PK\x03\x04" and produces
        # dozens of "headers" from padding. Only the end-of-central-directory
        # record, which carries its own comment length and offset, counts.
        locals_found = len(_zip_entries(blob)) if has_end else blob.count(b"PK\x03\x04")
        score = 1 + (2 if has_end else 0) + (1 if has_end and locals_found else 0)
        return score, has_end, ("EOCD present, %d entries" % locals_found if has_end
                                else f"{locals_found} local-header-like runs, no EOCD")
    if kind == "gzip":
        try:
            inflated = zlib.decompress(blob, 47)
            return 4, True, f"valid gzip, {len(inflated)} bytes"
        except zlib.error as error:
            return 1, False, f"gzip does not inflate: {error}"
    # Formats with no cheap checksum can only ever score the magic itself.
    return 1, False, "magic only (this format carries no cheap checksum)"


def _zip_entries(blob: bytes) -> list[str]:
    """Entry names from the central directory, which is self-describing."""
    end = blob.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 > len(blob):
        return []
    count = struct.unpack_from("<H", blob, end + 10)[0]
    offset = struct.unpack_from("<I", blob, end + 16)[0]
    names: list[str] = []
    for _ in range(min(count, 200)):
        if offset + 46 > len(blob) or blob[offset:offset + 4] != b"PK\x01\x02":
            break
        name_len = struct.unpack_from("<H", blob, offset + 28)[0]
        extra_len = struct.unpack_from("<H", blob, offset + 30)[0]
        comment_len = struct.unpack_from("<H", blob, offset + 32)[0]
        name = blob[offset + 46:offset + 46 + name_len]
        names.append(name.decode("utf-8", "replace"))
        offset += 46 + name_len + extra_len + comment_len
    return names


def try_pad(blob: bytes, stride: int, anchor: int) -> list[dict]:
    """Derive a repeating pad from a forced magic near a framing anchor.

    The anchor is where the record magic was found, which is normally a few
    bytes into the record rather than at its start, so the payload offset is
    searched around it instead of assumed.
    """
    findings = []
    low = max(0, anchor - 16)
    for base in range(low, min(anchor + stride, len(blob) - 8)):
        if base + 8 > len(blob):
            break
        for kind, magic in MAGICS:
            window = blob[base:base + len(magic)]
            if len(window) < len(magic):
                continue
            pad = bytes(a ^ b for a, b in zip(window, magic))
            period = pad_period(pad)
            if period is None or period > 4 or len(magic) < 4:
                continue
            plain = apply_pad(blob[base:], pad[:period])
            score, ok, note = validate(kind, plain)
            findings.append({
                "kind": kind, "offset": base - anchor, "period": period,
                "key": pad[:period], "valid": ok, "note": note, "plain": plain,
                "score": score + (2 if ok else 0),
            })
    return findings


def carve_objects(blob: bytes, out_dir: Path, limit: int = 8) -> list[str]:
    """Save every embedded object whose magic is present, validated when possible."""
    written = []
    for kind, magic in MAGICS:
        start = blob.find(magic)
        if start < 0:
            continue
        end = len(blob)
        if kind == "png":
            marker = blob.find(b"IEND", start)
            if marker > 0:
                end = marker + 8
        elif kind == "zip":
            marker = blob.rfind(b"PK\x05\x06")
            if marker > start:
                end = marker + 22
        payload = blob[start:end]
        _, ok, note = validate(kind, payload)
        target = out_dir / f"carved-{kind}-{start:#x}.bin"
        target.write_bytes(payload)
        written.append(f"{target.name} ({len(payload)} bytes, "
                       f"{'valid' if ok else 'INVALID'}: {note})")
        if len(written) >= limit:
            break
    return written


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture")
    parser.add_argument("--out", default="", help="directory for carved objects")
    parser.add_argument("--hex", type=int, default=48, help="hexdump bytes per stream (0 = off)")
    parser.add_argument("--stream", default="", help="only this stream index, e.g. 0")
    parser.add_argument("--max-segments", type=int, default=200000)
    args = parser.parse_args()

    segments = read_capture(args.capture)
    if len(segments) > args.max_segments:
        print(f"capture has {len(segments)} segments; only the first {args.max_segments} are read")
        segments = segments[:args.max_segments]
    streams, overlaps, segment_count = reassemble(segments)
    total_bytes = sum(len(v) for v in streams.values())
    print(f"capture: {len(segments)} transport segments, {len(streams)} conversations, "
          f"{total_bytes} payload bytes in {segment_count} segments")
    if overlaps:
        print(f"note: {sum(overlaps.values())} duplicate sequence numbers "
              f"(retransmissions) were collapsed by sequence order")
    print()

    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    ordered = sorted(streams.items(), key=lambda item: -len(item[1]))
    for index, (key, blob) in enumerate(ordered):
        if args.stream and str(index) != args.stream:
            continue
        src, sport, dst, dport = key
        print(f"[stream {index}] {src}:{sport} -> {dst}:{dport}  {len(blob)} bytes")
        print(f"  entropy {entropy(blob):.2f} bits/byte, printable {printable_ratio(blob):.2f}")
        if args.hex:
            head = blob[:args.hex].hex(" ")
            tail = blob[-args.hex:].hex(" ") if len(blob) > args.hex else ""
            print(f"  head {head}")
            if tail:
                print(f"  tail {tail}")

        framing = find_framing(blob)
        if framing:
            stride, magic = framing
            first = blob.find(magic)
            records = (len(blob) - first) // stride
            print(f"  framing: {records} records of {stride} bytes, "
                  f"magic {magic.hex(' ')} at offset {first} (gap {stride})")
            findings = try_pad(blob, stride, first)
            if findings:
                ranked = sorted(findings, key=lambda item: item["score"], reverse=True)
                best = ranked[0]
                strong = [item for item in findings if item["score"] >= 3]
                if strong:
                    print(f"  payload pad: {best['kind']} magic at anchor{best['offset']:+d}, "
                          f"period {best['period']}, key {best['key'].hex(' ')}")
                    print(f"  validity: {best['note']}")
                else:
                    print("  payload pad: no candidate reached a structural milestone; "
                          "every magic match here is chance or filler, do not trust one")
                    plain = None
                print(f"  candidates: {len(findings)} magic matches, "
                      f"{len(strong)} reach a structural milestone (score >= 3)")
                if strong:
                    for item in ranked[1:4]:
                        if item["score"] >= 2:
                            print(f"    also: {item['kind']} anchor{item['offset']:+d} "
                                  f"period {item['period']} score {item['score']} - {item['note']}")
                else:
                    for item in ranked[:3]:
                        print(f"    rejected: {item['kind']} anchor{item['offset']:+d} "
                              f"period {item['period']} score {item['score']} - {item['note']}")
                plain = best["plain"] if strong else None
                if out_dir:
                    source = plain if plain is not None else blob
                    if plain is not None:
                        decoded = out_dir / f"stream{index}-decoded.bin"
                        decoded.write_bytes(plain)
                        print(f"  wrote {decoded}")
                    for line in carve_objects(source, out_dir):
                        print(f"  carved {line}")
            else:
                print("  payload pad: none - no forced magic decodes to a repeating pad")
                if out_dir:
                    for line in carve_objects(blob, out_dir):
                        print(f"  carved {line}")
        else:
            print("  framing: no fixed-size record magic found")
            if out_dir:
                for line in carve_objects(blob, out_dir):
                    print(f"  carved {line}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
