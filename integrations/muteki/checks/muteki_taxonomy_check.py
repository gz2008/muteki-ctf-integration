"""Offline checks for the category prior and its staging path."""
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

from muteki.solver import ctf_taxonomy as tax  # noqa: E402

assert tax.available_categories() == (
    "web", "pwn", "reverse", "crypto", "forensics", "misc"
), tax.available_categories()

for category in tax.available_categories():
    prior = tax.category_prior(category)
    assert prior.startswith("## Category action prior"), category
    assert "completion state" in prior, category
    assert "not evidence" in prior, category
    print(f"{category}: {len(prior)} bytes")

pwn = tax.category_prior("pwn")
assert "`leak_offset` (probe, 2u)" in pwn, pwn
assert "first: " in pwn and "escalate only with evidence" in pwn
assert tax.category_prior("osint") == ""
assert tax.category_prior("") == ""
assert tax.taxonomy_path("osint") is None

# worker_skills staging: needs a stub for the heavy prompt import
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
with tempfile.TemporaryDirectory(prefix="muteki-taxonomy-") as temporary:
    root = Path(temporary)
    staged = ws.stage_ctf_playbook_skill(root / "pwn", engine="codex", category="pwn")
    assert staged, "staging returned nothing"
    target = root / "pwn" / ".muteki-skills" / name
    prior_file = target / "references" / "category-prior.md"
    assert prior_file.is_file(), "category prior was not staged"
    assert "leak_offset" in prior_file.read_text(encoding="utf-8")

    staged = ws.stage_ctf_playbook_skill(root / "nocat", engine="codex")
    target = root / "nocat" / ".muteki-skills" / name
    assert (target / "SKILL.md").is_file()
    assert not (target / "references" / "category-prior.md").exists()

print("taxonomy checks OK")
