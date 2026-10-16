"""Offline checks for the generated Worker tool index."""
from __future__ import annotations

import os
import sys
import tempfile
import types
from pathlib import Path

_configured = os.environ.get("MUTEKI_REPO", "").strip()
REPO = Path(_configured).expanduser() if _configured else None
if not (REPO and REPO.is_dir()):
    raise SystemExit("set MUTEKI_REPO to the Project Muteki checkout, e.g. MUTEKI_REPO=/opt/muteki")
sys.path.insert(0, str(REPO))

import muteki.solver  # noqa: E402

contract = "stub"
stub = types.ModuleType("muteki.solver.cli_prompts")
stub.CTF_ROLE_CONTRACT = contract
stub._CTF_WORKER_SYSTEM = contract
stub._CTF_FACT_ASSERTION_NOTE = "stub"
sys.modules["muteki.solver.cli_prompts"] = stub
setattr(sys.modules["muteki.solver"], "cli_prompts", stub)

from muteki.solver import worker_skills as ws  # noqa: E402

name = ws.CTF_PLAYBOOK_SKILL_NAME

with tempfile.TemporaryDirectory(prefix="muteki-toolindex-") as temporary:
    root = Path(temporary)
    tool_root = root / "toolbox-root"
    (tool_root / "bin").mkdir(parents=True)
    for command in ("ctf-corpus", "ropper", "pwninit", "ysoserial"):
        (tool_root / "bin" / command).write_text("#!/bin/sh\n", encoding="utf-8")
    (tool_root / "knowledges").mkdir()
    (tool_root / "knowledges" / "how2heap").mkdir()
    (tool_root / "pocs").mkdir()
    (tool_root / "pocs" / "vulhub").mkdir()
    (tool_root / "wordlists").mkdir()
    (tool_root / "nuclei-templates").mkdir()

    os.environ["MUTEKI_LOCAL_WORKER_ROOT"] = str(tool_root)
    try:
        index = ws.tool_index_text()
        assert "exposes 4 commands" in index, index
        assert "`ctf-corpus`" in index and "`ysoserial`" in index, index
        assert "./toolbox/knowledge" in index and "./toolbox/pocs" in index, index
        assert "./toolbox/wordlists" not in index, "empty corpora must be omitted"

        staged = ws.stage_ctf_playbook_skill(root / "worker", engine="codex", category="pwn")
        assert staged
        target = root / "worker" / ".muteki-skills" / name
        index_file = target / "references" / "tool-index.md"
        assert index_file.is_file(), "tool index was not staged"
        text = index_file.read_text(encoding="utf-8")
        assert "exposes 4 commands" in text
        assert (target / "references" / "category-prior.md").is_file()

        # container Workers get the enumeration hint instead of a host listing
        container_index = ws.tool_index_text(container=types.SimpleNamespace(image="x"))
        assert "enumerate the projected tool root" in container_index, container_index
    finally:
        os.environ.pop("MUTEKI_LOCAL_WORKER_ROOT", None)

print("tool index checks OK")
