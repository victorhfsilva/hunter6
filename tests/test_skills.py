"""Skill library tests — discovery, frontmatter, search, index, tool wiring."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6.scope import Scope  # noqa: E402
from hunter6.skills import SkillLibrary, default_skill_roots  # noqa: E402
from hunter6.tools import FindingsStore, ToolBox  # noqa: E402


def _make_skill(root: Path, name: str, description: str, body: str = "## playbook\n") -> Path:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\n{body}",
        encoding="utf-8",
    )
    return d


def test_discover_and_get(tmp_path: Path):
    _make_skill(tmp_path, "hunt-sqli", "SQL injection playbook")
    _make_skill(tmp_path, "hunt-xss", "XSS playbook")
    lib = SkillLibrary([tmp_path]).discover()
    assert len(lib) == 2
    assert lib.get("hunt-sqli").description == "SQL injection playbook"
    assert lib.get("HUNT-XSS") is not None
    assert lib.get("missing") is None


def test_frontmatter_block_scalar(tmp_path: Path):
    d = tmp_path / "acl-abuse"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\n"
        "name: acl-abuse\n"
        "description: >\n"
        "  Exploits misconfigured AD ACLs.\n"
        "  Covers GenericAll and WriteDACL.\n"
        "keywords:\n"
        "  - ACL\n"
        "---\n\nbody\n",
        encoding="utf-8",
    )
    lib = SkillLibrary([tmp_path]).discover()
    desc = lib.get("acl-abuse").description
    assert "Exploits misconfigured AD ACLs." in desc
    assert "Covers GenericAll" in desc
    assert ">" not in desc


def test_first_root_wins(tmp_path: Path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    _make_skill(a, "dup", "from a")
    _make_skill(b, "dup", "from b")
    lib = SkillLibrary([a, b]).discover()
    assert lib.get("dup").description == "from a"


def test_missing_root_skipped(tmp_path: Path):
    _make_skill(tmp_path, "real", "exists")
    lib = SkillLibrary([tmp_path / "nope", tmp_path]).discover()
    assert lib.names() == ["real"]


def test_search_ranks_name_matches(tmp_path: Path):
    _make_skill(tmp_path, "hunt-sqli", "SQL injection playbook")
    _make_skill(tmp_path, "hunt-nosqli", "NoSQL injection playbook")
    _make_skill(tmp_path, "hunt-xss", "XSS playbook")
    lib = SkillLibrary([tmp_path]).discover()
    results = lib.search("sqli")
    names = [s.name for s in results]
    assert "hunt-sqli" in names
    assert "hunt-xss" not in names


def test_index_block_compact(tmp_path: Path):
    _make_skill(tmp_path, "hunt-idor", "IDOR playbook " + "x" * 400)
    lib = SkillLibrary([tmp_path]).discover()
    block = lib.index_block(desc_chars=60)
    assert "- hunt-idor:" in block
    line = block.splitlines()[0]
    assert len(line) < 120


def test_default_roots_explicit_wins(tmp_path: Path):
    roots = default_skill_roots([str(tmp_path)])
    assert roots == [tmp_path]


def test_default_roots_env(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HUNTER6_SKILLS", f"{tmp_path}/a{__import__('os').pathsep}{tmp_path}/b")
    roots = default_skill_roots(None)
    assert [str(r) for r in roots] == [f"{tmp_path}/a", f"{tmp_path}/b"]


def test_default_roots_falls_back_to_opencode(monkeypatch):
    monkeypatch.delenv("HUNTER6_SKILLS", raising=False)
    roots = default_skill_roots(None)
    # Either real candidate dirs exist, or the OpenCode fallback is returned.
    assert roots
    assert any("opencode" in str(r) or r.name == "skills" for r in roots)


def test_toolbox_skill_tools(tmp_path: Path):
    _make_skill(tmp_path, "hunt-sqli", "SQL injection playbook", "## UNION first\n")
    lib = SkillLibrary([tmp_path]).discover()
    box = ToolBox(
        scope=Scope.from_target("example.com"),
        findings=FindingsStore(tmp_path),
        skills=lib,
    )
    assert "hunt-sqli" in box.list_skills()
    full = box.read_skill("hunt-sqli")
    assert "# SKILL: hunt-sqli" in full
    assert "UNION first" in full
    assert "unknown skill" in box.read_skill("nope")
    assert "hunt-sqli" in box.search_skills("sql")


def test_toolbox_without_skills(tmp_path: Path):
    box = ToolBox(scope=Scope.from_target("example.com"), findings=FindingsStore(tmp_path))
    assert box.list_skills() == "no skills loaded"
    assert box.read_skill("x").startswith("[error]")
