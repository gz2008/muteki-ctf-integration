"""Hash length-extension helper for MAC(secret || message || extra).

The attack never needs the secret: knowing len(secret) is enough to reforge the
MAC of message || glue_padding || extra with the original digest as the new IV.
The key length is the one unknown, so this prints every plausible candidate in a
form that can be pasted straight into a request; the target itself is the oracle
that says which one is right.

Usage:
  ctf-hashpump --mac 6f5f... --data "user=guest" --append ";admin=true"
  ctf-hashpump --mac ... --data ... --append ... --keylen 8
  ctf-hashpump --mac ... --data ... --append ... --keylen-range 1-16 --format url
"""
from __future__ import annotations

import argparse
import sys
from urllib.parse import quote

try:
    import hashpumpy
except ImportError:  # pragma: no cover - reported to the operator
    print("hashpumpy is not installed; run provision-tool-gaps.sh fourth-batch",
          file=sys.stderr)
    raise SystemExit(2)

ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def parse_range(text: str) -> list[int]:
    if "-" in text:
        low, high = text.split("-", 1)
        return list(range(int(low), int(high) + 1))
    return [int(text)]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mac", required=True,
                        help="the digest the server produces (hex)")
    parser.add_argument("--data", required=True,
                        help="the message the server signed (without the secret)")
    parser.add_argument("--append", required=True,
                        help="what to append after the padding")
    parser.add_argument("--keylen", type=int, default=0,
                        help="secret length, if known")
    parser.add_argument("--keylen-range", default="1-32",
                        help="secret lengths to try when --keylen is absent (default 1-32)")
    parser.add_argument("--format", choices=("raw", "hex", "url", "repr"),
                        default="url", help="how to print the forged payload")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after N candidates (default: all)")
    args = parser.parse_args()

    mac = args.mac.strip().lower()
    if len(mac) not in ALGORITHMS:
        print(f"unrecognised digest length {len(mac)} hex chars; expected one of "
              f"{sorted(ALGORITHMS)}", file=sys.stderr)
        return 2
    algorithm = ALGORITHMS[len(mac)]
    lengths = [args.keylen] if args.keylen else parse_range(args.keylen_range)

    print(f"# {algorithm} MAC(secret || message), forging secret || message || padding || append")
    print(f"# original mac : {mac}")
    print(f"# original data: {args.data!r}")
    print(f"# append       : {args.append!r}")
    print()

    printed = 0
    for keylen in lengths:
        new_mac, new_data = hashpumpy.hashpump(mac, args.data, args.append, keylen)
        if args.format == "raw":
            payload = new_data.decode("latin-1")
        elif args.format == "hex":
            payload = new_data.hex()
        elif args.format == "repr":
            payload = repr(new_data)
        else:
            payload = quote(new_data, safe="")
        print(f"keylen={keylen} mac={new_mac}")
        print(f"  payload[{args.format}]={payload}")
        printed += 1
        if args.limit and printed >= args.limit:
            break

    print()
    print("The glue padding is binary; send the payload in a form the target accepts")
    print("(URL-encoded parameter or cookie, or raw bytes on a socket). The server")
    print("accepting one candidate and rejecting the rest is the verification step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
