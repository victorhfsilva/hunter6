"""Scope model for hunter6.

Why this exists
---------------
Validation testing must never touch a host the operator did not hand us. The
parent framework solved this with a whole-run gate that dead-ended on missing
bookkeeping. hunter6 instead derives scope **from the scanned subdomains
themselves**, takes one explicit acknowledgement, and enforces the boundary
**per request** inside the HTTP tool. So:

* No pre-existing scope files are required: the scan folder defines the hosts.
* If you do have a scope file, it is honored and tightened.
* Every request is checked; a denied request is skipped and logged — it does
  not abort the whole run.

Modes
-----
``auto``       default. Scope = the target host plus its subdomains.
``strict``     Scope = the exact target host only (no subdomains).
``file``       Scope loaded from a scope file (yaml or plain text).
``off``        No host restriction (prints a loud warning). Use only when the
               operator has already constrained the tool some other way.

Out-of-scope entries always win over in-scope entries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

MODES = ("auto", "strict", "file", "off")

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def normalize_host(value: str) -> str:
    """Turn a URL or bare host into a lowercase hostname (no port, no path)."""
    value = (value or "").strip()
    if not value:
        return ""
    if _SCHEME_RE.match(value):
        host = urlsplit(value).hostname or ""
    else:
        # Strip a path/query if someone passed "example.com/api?x=1".
        host = value.split("/", 1)[0]
        host = host.split("?", 1)[0]
        # Strip userinfo and port. Keep IPv6 brackets off for matching.
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        if host.startswith("["):
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:
            host = host.split(":", 1)[0]
    host = host.strip().strip(".").lower()
    return host


def _normalize_pattern(value: str) -> str:
    """Normalize a scope entry, preserving a leading ``*.`` wildcard."""
    value = (value or "").strip()
    if not value:
        return ""
    if value.startswith("*."):
        return "*." + normalize_host(value[2:])
    if value.startswith("."):
        return "." + normalize_host(value[1:])
    return normalize_host(value)


def _pattern_matches(pattern: str, host: str) -> bool:
    """Match a scope pattern against a host.

    Supports exact hosts, ``*.example.com`` wildcards, and a bare
    ``example.com`` which also matches subdomains when ``allow_subdomains``
    is applied by the caller (see :meth:`Scope.allows`).
    """
    pattern = pattern.strip().lower().strip(".")
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    if pattern.startswith("."):
        base = pattern[1:]
        return host == base or host.endswith("." + base)
    return host == pattern


@dataclass
class Scope:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    mode: str = "auto"
    authorized: bool = False
    source: str = "derived"
    notes: list[str] = field(default_factory=list)

    # -- constructors ---------------------------------------------------

    @classmethod
    def from_target(cls, target: str, *, mode: str = "auto") -> "Scope":
        host = normalize_host(target)
        allow_sub = mode != "strict"
        return cls(
            in_scope=[host] if host else [],
            allow_subdomains=allow_sub,
            mode=mode,
            authorized=True,
            source=f"derived:{mode}",
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        in_scope: list[str] = []
        out_of_scope: list[str] = []
        if p.suffix.lower() in (".yaml", ".yml"):
            section = None
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].rstrip()
                if not line.strip():
                    continue
                if not line.startswith((" ", "\t")) and ":" in line:
                    key = line.split(":", 1)[0].strip().lower()
                    section = key if key in ("in_scope", "out_of_scope") else None
                    continue
                if section:
                    item = line.strip().lstrip("-").strip().strip("'\"")
                    if item:
                        (in_scope if section == "in_scope" else out_of_scope).append(item)
        else:
            # Plain-text scope: one host per line. Tolerates URLs, ports,
            # bullet markers, inline comments, and "host  # note" lines.
            section = "in_scope"
            for raw in text.splitlines():
                marker = raw.strip().lower()
                if marker.startswith(("#", "//")):
                    if "out of scope" in marker or "out_of_scope" in marker or "exclude" in marker:
                        section = "out_of_scope"
                    elif "in scope" in marker or "in_scope" in marker:
                        section = "in_scope"
                    continue
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                item = line.lstrip("-*").strip().strip("'\"")
                if not item:
                    continue
                # If the line has extra words, take the first host-like token.
                token = item.split()[0] if " " in item else item
                if token:
                    (in_scope if section == "in_scope" else out_of_scope).append(token)
        scope = cls(
            in_scope=[h for h in (_normalize_pattern(x) for x in in_scope) if h],
            out_of_scope=[h for h in (_normalize_pattern(x) for x in out_of_scope) if h],
            allow_subdomains=True,
            mode="file",
            authorized=True,
            source=str(p),
        )
        return scope

    @classmethod
    def from_hosts(
        cls,
        hosts: list[str],
        *,
        allow_subdomains: bool = True,
        out_of_scope: list[str] | None = None,
        source: str = "explicit",
    ) -> "Scope":
        """Build a scope from an explicit list of in-scope hosts/patterns.

        Used by ``--in-scope`` (a subdomain on the command line) and
        ``--scope-file`` (a txt with one subdomain per line). Entries are
        normalized but wildcards (``*.x``) and bare apexes are preserved.
        """
        cleaned = [h for h in (_normalize_pattern(x) for x in hosts) if h]
        return cls(
            in_scope=cleaned,
            out_of_scope=[normalize_host(e) for e in (out_of_scope or []) if e],
            allow_subdomains=allow_subdomains,
            mode="file",
            authorized=True,
            source=source,
        )

    @classmethod
    def load(
        cls,
        target: str,
        *,
        mode: str = "auto",
        scope_file: str | None = None,
        excludes: list[str] | None = None,
    ) -> "Scope":
        if scope_file:
            scope = cls.from_file(scope_file)
        elif mode == "off":
            scope = cls(
                in_scope=["*"],
                allow_subdomains=True,
                mode="off",
                authorized=True,
                source="off",
            )
            scope.notes.append("scope enforcement disabled — every host is allowed")
        else:
            scope = cls.from_target(target, mode=mode)
        if excludes:
            scope.out_of_scope.extend(normalize_host(e) for e in excludes if e)
        return scope

    # -- matching -------------------------------------------------------

    def allows(self, target: str) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for a URL or host."""
        host = normalize_host(target)
        if not host:
            return False, "empty host"
        if self.mode == "off":
            return True, "scope off"
        for pattern in self.out_of_scope:
            if _pattern_matches(pattern, host):
                return False, f"out-of-scope pattern '{pattern}'"
        for pattern in self.in_scope:
            if pattern == "*":
                return True, "wildcard"
            if _pattern_matches(pattern, host):
                return True, f"in-scope '{pattern}'"
            # Bare apex also covers subdomains in permissive/auto mode.
            if self.allow_subdomains and not pattern.startswith(("*", ".")):
                base = normalize_host(pattern)
                if base and host.endswith("." + base):
                    return True, f"subdomain of '{pattern}'"
        return False, "host not in scope"

    def check_url(self, url: str) -> tuple[bool, str]:
        return self.allows(url)

    def describe(self) -> str:
        lines = [
            f"mode       : {self.mode}",
            f"source     : {self.source}",
            f"authorized : {self.authorized}",
            f"subdomains : {self.allow_subdomains}",
            f"in-scope   : {', '.join(self.in_scope) or '(none)'}",
            f"out-scope  : {', '.join(self.out_of_scope) or '(none)'}",
        ]
        for note in self.notes:
            lines.append(f"note       : {note}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "source": self.source,
            "authorized": self.authorized,
            "allow_subdomains": self.allow_subdomains,
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
        }
