"""Skill library for hunter6.

A skill is a directory containing ``SKILL.md`` (YAML frontmatter with at least
``name`` and ``description``). This is the same layout OpenCode, Claude Code,
and the agentskills.io standard use.

hunter6 loads skills from, in order:

1. ``--skills DIR`` (repeatable) — an explicit folder wins.
2. ``HUNTER6_SKILLS`` (``os.pathsep``-separated).
3. ``./skills`` (project-local).
4. ``~/.config/opencode/skills`` (OpenCode default).
5. ``~/.agents/skills``.

The AI never receives every skill body up front (that would be hundreds of
thousands of tokens). Instead it gets a compact **index** (name + description)
and loads full methodology on demand with the ``read_skill`` tool — the
standard progressive-disclosure pattern.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


@dataclass
class Skill:
    name: str
    description: str
    body: str
    path: Path
    root: Path
    supporting: int = 0

    def source_label(self) -> str:
        try:
            return str(self.path.relative_to(self.root))
        except ValueError:
            return str(self.path)


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    fm: dict = {}
    lines = m.group(1).splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        i += 1
        if not raw or raw.lstrip().startswith("#") or ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        value = value.strip()

        # YAML block scalar (``>`` folded or ``|`` literal): collect the
        # indented block that follows.
        if value in (">", "|", ">-", "|-", ">+", "|+"):
            block: list[str] = []
            while i < len(lines):
                nxt = lines[i]
                if nxt.strip() and not nxt.startswith((" ", "\t")):
                    break
                block.append(nxt.strip())
                i += 1
            text_block = (" " if value.startswith(">") else "\n").join(
                b for b in block if b
            )
            fm[key] = text_block.strip()
            continue

        # Quoted scalars.
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]

        # Simple inline list (``[a, b]``).
        if value.startswith("[") and value.endswith("]"):
            fm[key] = [v.strip() for v in value[1:-1].split(",") if v.strip()]
            continue

        fm[key] = value
    return fm, text[m.end():]


def default_skill_roots(explicit: list[str] | None = None) -> list[Path]:
    """Resolve which directories to scan for skills."""
    if explicit:
        return [Path(p).expanduser() for p in explicit]
    env = os.environ.get("HUNTER6_SKILLS", "")
    if env:
        return [Path(p).expanduser() for p in env.split(os.pathsep) if p.strip()]
    candidates = [
        Path.cwd() / "skills",
        Path.home() / ".config" / "opencode" / "skills",
        Path.home() / ".agents" / "skills",
    ]
    existing = [c for c in candidates if c.is_dir()]
    # Fall back to the OpenCode path even if absent, so the message is useful.
    return existing or [Path.home() / ".config" / "opencode" / "skills"]


class SkillLibrary:
    def __init__(self, roots: list[Path]):
        self.roots = [Path(r) for r in roots]
        self.skills: dict[str, Skill] = {}
        self.loaded_from: list[str] = []

    # -- discovery ------------------------------------------------------

    def discover(self) -> "SkillLibrary":
        self.skills.clear()
        self.loaded_from = []
        for root in self.roots:
            if not root.is_dir():
                continue
            found = 0
            for child in sorted(root.iterdir()):
                if not child.is_dir():
                    continue
                skill_md = child / "SKILL.md"
                if not skill_md.exists():
                    continue
                skill = self._load(child, skill_md, root)
                if skill and skill.name not in self.skills:
                    self.skills[skill.name] = skill
                    found += 1
            if found:
                self.loaded_from.append(f"{root} ({found})")
        return self

    @staticmethod
    def _load(dir_path: Path, skill_md: Path, root: Path) -> Skill | None:
        try:
            text = skill_md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        fm, body = _parse_frontmatter(text)
        supporting = sum(1 for f in dir_path.rglob("*") if f.is_file() and f.name != "SKILL.md")
        return Skill(
            name=str(fm.get("name") or dir_path.name),
            description=str(fm.get("description") or "").strip(),
            body=body.strip(),
            path=skill_md,
            root=root,
            supporting=supporting,
        )

    # -- access ---------------------------------------------------------

    def __len__(self) -> int:
        return len(self.skills)

    def names(self) -> list[str]:
        return sorted(self.skills)

    def get(self, name: str) -> Skill | None:
        if name in self.skills:
            return self.skills[name]
        low = name.strip().lower()
        for key, skill in self.skills.items():
            if key.lower() == low:
                return skill
        return None

    def search(self, query: str, limit: int = 20) -> list[Skill]:
        q = (query or "").strip().lower()
        if not q:
            return list(self.skills.values())[:limit]
        terms = [t for t in re.split(r"\W+", q) if t]
        scored: list[tuple[int, Skill]] = []
        for skill in self.skills.values():
            hay_name = skill.name.lower()
            hay = (skill.name + " " + skill.description).lower()
            score = 0
            for t in terms:
                if t in hay_name:
                    score += 3
                elif t in hay:
                    score += 1
            if score:
                scored.append((score, skill))
        scored.sort(key=lambda x: (-x[0], x[1].name))
        return [s for _, s in scored[:limit]]

    def index_block(self, max_skills: int = 400, desc_chars: int = 140) -> str:
        lines = []
        for name in self.names()[:max_skills]:
            desc = self.skills[name].description.replace("\n", " ")
            if len(desc) > desc_chars:
                desc = desc[: desc_chars - 1].rstrip() + "…"
            lines.append(f"- {name}: {desc}")
        return "\n".join(lines)

    def source_description(self) -> str:
        if not self.loaded_from:
            return f"none (looked in: {', '.join(str(r) for r in self.roots)})"
        return "; ".join(self.loaded_from)
