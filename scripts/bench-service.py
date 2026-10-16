"""Bring up a local benchmark challenge service outside the agent workdir.

Usage: python bench-service.py <challenge-dir> <state-file>

Writes {"url": "http://127.0.0.1:<port>/", "pid": <pid>} to the state file and
keeps serving until the parent kills the process. Only the ctf-suite local
challenge layout (`challenge.py` exposing `start_server`) is supported.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    challenge_dir = Path(sys.argv[1]).resolve()
    state_file = Path(sys.argv[2]).resolve()
    module_path = challenge_dir / "challenge.py"
    if not module_path.is_file():
        print(f"challenge.py not found in {challenge_dir}", file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("bench_challenge", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_challenge"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    start = getattr(module, "start_server", None)
    if start is None:
        print("challenge.py does not expose start_server", file=sys.stderr)
        return 4
    server, _thread = start()
    port = server.server_port
    state_file.write_text(
        json.dumps({"url": f"http://127.0.0.1:{port}/", "pid": __import__("os").getpid()}),
        encoding="utf-8",
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
