"""Deterministic check that the planner prompt carries the category prior."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_configured = os.environ.get("MUTEKI_REPO", "").strip()
REPO = Path(_configured).expanduser() if _configured else None
if not (REPO and REPO.is_dir()):
    raise SystemExit("set MUTEKI_REPO to the Project Muteki checkout, e.g. MUTEKI_REPO=/opt/muteki")
sys.path.insert(0, str(REPO))

from muteki.solver.reason import build_reason_prompt  # noqa: E402

pwn = build_reason_prompt("GRAPH-SUMMARY", category="pwn")
user = pwn[-1]["content"]
assert "共享求解图" in user
assert "## Category action prior" in user, user
assert "`leak_offset` (probe, 2u)" in user, user
assert "只输出规划 JSON。" in user
assert user.count("## Category action prior") == 1

reverse = build_reason_prompt("GRAPH-SUMMARY", category="reverse")
assert "## Category action prior" in reverse[-1]["content"]
assert "- category: `rev`" in reverse[-1]["content"], reverse[-1]["content"]

plain = build_reason_prompt("GRAPH-SUMMARY")
assert "Category action prior" not in plain[-1]["content"], "prior must not leak without a category"

unknown = build_reason_prompt("GRAPH-SUMMARY", category="osint")
assert "Category action prior" not in unknown[-1]["content"]

try:
    build_reason_prompt("GRAPH-SUMMARY", mode="pentest")
except ValueError:
    pass
else:
    raise AssertionError("non-CTF mode must still be rejected")

print("reason prior checks OK")
