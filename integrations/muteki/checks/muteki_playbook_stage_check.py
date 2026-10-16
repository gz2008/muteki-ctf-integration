"""Offline check for stage_ctf_playbook_skill without heavy Muteki deps."""
from __future__ import annotations

import json
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

import muteki.solver  # noqa: E402  (package inits are empty)

contract = "stub-ctf-role-contract"
stub = types.ModuleType("muteki.solver.cli_prompts")
stub.CTF_ROLE_CONTRACT = contract
stub._CTF_WORKER_SYSTEM = contract          # worker_skills asserts identity
stub._CTF_FACT_ASSERTION_NOTE = "stub-note"
sys.modules["muteki.solver.cli_prompts"] = stub
setattr(sys.modules["muteki.solver"], "cli_prompts", stub)

from muteki.solver import worker_skills as ws  # noqa: E402
from muteki import capability_management as cm  # noqa: E402

NAME = ws.CTF_PLAYBOOK_SKILL_NAME
source = Path(ws.__file__).resolve().parents[2] / "skills" / NAME
assert (source / "SKILL.md").is_file(), f"skill source missing: {source}"
for category in ("web", "pwn", "reverse", "crypto", "forensics", "misc"):
    assert (source / "references" / f"{category}.md").is_file(), category

with tempfile.TemporaryDirectory(prefix="muteki-playbook-check-") as temporary:
    root = Path(temporary)

    # 1. enabled CTF worker: physical copy + relative symlinks per engine root
    ctf_root = root / "ctf"
    staged = ws.stage_ctf_playbook_skill(ctf_root, engine="codex", mode="ctf")
    expected = [
        str(ctf_root / relative / NAME)
        for relative in ws.project_skill_roots("codex")
    ]
    assert staged == expected, (staged, expected)
    assert len(staged) >= 2, "codex should project into at least two roots"
    kinds = set()
    for path in staged:
        link = Path(path)
        assert link.is_dir(), f"symlink does not resolve: {link}"
        assert (link / "SKILL.md").is_file(), f"SKILL.md invisible: {link}"
        assert (link / "references" / "pwn.md").is_file(), f"references missing: {link}"
        kinds.add("symlink" if link.is_symlink() else "copy")
    assert (ctf_root / ".muteki-skills" / NAME / "SKILL.md").is_file()
    print("projection kind:", ",".join(sorted(kinds)))

    # 2. re-staging is idempotent
    assert ws.stage_ctf_playbook_skill(ctf_root, engine="codex", mode="ctf") == expected

    # 3. operator-provided Skill content is preserved
    operator_root = root / "operator"
    own = operator_root / ".codex" / "skills" / NAME
    own.mkdir(parents=True)
    (own / "SKILL.md").write_text("operator content", encoding="utf-8")
    ws.stage_ctf_playbook_skill(operator_root, engine="codex", mode="ctf")
    assert (own / "SKILL.md").read_text(encoding="utf-8") == "operator content"

    # 4. penetration-testing Workers are skipped
    assert ws.stage_ctf_playbook_skill(root / "pentest", engine="codex", mode="pentest") == []
    assert not (root / "pentest").exists(), "pentest workspace must stay untouched"

    # 5. a disabled capability stages nothing
    state = root / "capability.json"
    state.write_text(json.dumps({"skills": {NAME: False}}), encoding="utf-8")
    cm.configure(state)
    assert cm.enabled("skills", NAME) is False
    assert ws.stage_ctf_playbook_skill(root / "disabled", engine="codex", mode="ctf") == []
    assert not (root / "disabled").exists()
    cm.configure(root / "no-such-capability.json")   # back to defaults
    assert cm.enabled("skills", NAME) is True

    # 6. a missing source is not fatal
    original = ws._REPO_CTF_PLAYBOOK_SKILL
    ws._REPO_CTF_PLAYBOOK_SKILL = root / "absent"
    try:
        assert ws.stage_ctf_playbook_skill(root / "absent-run", engine="codex") == []
    finally:
        ws._REPO_CTF_PLAYBOOK_SKILL = original

print("playbook staging check OK")

# 7. CTF worker prompts still format, and now point at the playbook
driver_stub = types.ModuleType("muteki.solver.cli_driver")
driver_stub.KB_MCP_NAME = ""
sys.modules["muteki.solver.cli_driver"] = driver_stub
setattr(sys.modules["muteki.solver"], "cli_driver", driver_stub)

# drop the section-1 stub so the real prompt module loads
sys.modules.pop("muteki.solver.cli_prompts", None)
if hasattr(sys.modules["muteki.solver"], "cli_prompts"):
    delattr(sys.modules["muteki.solver"], "cli_prompts")

from muteki.solver import cli_prompts as cp  # noqa: E402

explore = cp._EXPLORE_PROMPT.format(ctx="C", kb="K", intent_goal="G", fmt="flag{...}")
exec_prompt = cp._EXEC_PROMPT.format(ctx="C", kb="K", fmt="flag{...}")
checkpoint = cp._CHECKPOINT_PROMPT.format(
    intent_goal="G", expected_observable="E", stop_condition="S", ctx="C")
for text in (explore, exec_prompt):
    assert NAME in text, "CTF worker prompt does not point at the playbook"
assert "references/" in explore and "方法论索引" in explore
assert NAME not in checkpoint, "checkpoint prompt is not a playbook consumer"
assert cp.CTF_ROLE_CONTRACT is cp._CTF_WORKER_SYSTEM
print("CTF prompt formatting check OK")

# 8. the packaged-desktop acceptance script stays syntactically valid
builder = (REPO / "scripts" / "build_desktop_runtime.py").read_text(encoding="utf-8")
start = builder.index("    check = r'''") + len("    check = r'''")
end = builder.index("'''\n", start)
inner = builder[start:end]
compile(inner, "build_desktop_runtime.check", "exec")
assert "stage_ctf_playbook_skill" in inner
print("desktop runtime check snippet compiles OK")
