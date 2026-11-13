"""Tool surface the AI uses to hunt, with per-request scope enforcement.

Every network tool routes through :meth:`ToolBox._check`, which consults the
:class:`~hunter6.scope.Scope`. A denied request is **skipped and logged**; the
run continues. That is the core difference from a whole-run scope gate.
"""
from __future__ import annotations

import json
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .scope import Scope
from .skills import SkillLibrary

MAX_BODY = 12_000
DEFAULT_UA = "hunter6/0.1 (+authorized-assessment)"

_DENY_COMMANDS = (
    "rm -rf /", "mkfs", "dd if=", "> /dev/sd", ":(){:|:&};:", "shutdown", "reboot",
)


@dataclass
class Finding:
    title: str
    severity: str
    vuln_class: str
    url: str
    evidence: str
    confidence: str = "medium"
    status: str = "validated"     # validated | candidate
    source: str = ""


@dataclass
class FindingsStore:
    """Per-subdomain findings writer.

    ``stem`` lets each host write its own ``FINDINGS/<host>.md`` +
    ``<host>.json`` without clobbering siblings.
    """

    out_dir: Path
    stem: str = "FINDINGS"
    items: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.items.append(finding)

    def save(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / f"{self.stem}.json").write_text(
            json.dumps([f.__dict__ for f in self.items], indent=2), encoding="utf-8"
        )
        (self.out_dir / f"{self.stem}.md").write_text(self.render(), encoding="utf-8")

    def render(self) -> str:
        validated = [f for f in self.items if f.status == "validated"]
        candidates = [f for f in self.items if f.status != "validated"]
        lines = [f"# FINDINGS — {self.stem}", ""]
        lines.append(f"Validated: {len(validated)}  ·  Candidates: {len(candidates)}")
        lines.append("")

        def section(title: str, rows: list[Finding]) -> None:
            lines.append(f"## {title}")
            lines.append("")
            if not rows:
                lines.append("_None._")
                lines.append("")
                return
            for i, f in enumerate(rows, 1):
                lines.extend([
                    f"### {i}. {f.title}",
                    "",
                    f"- **Severity:** {f.severity}",
                    f"- **Class:** {f.vuln_class}",
                    f"- **Confidence:** {f.confidence}",
                    f"- **Status:** {f.status}",
                ])
                if f.url:
                    lines.append(f"- **URL:** {f.url}")
                if f.source:
                    lines.append(f"- **Source:** `{f.source}`")
                lines.extend([
                    "",
                    "**Evidence**",
                    "",
                    "```",
                    f.evidence.strip(),
                    "```",
                    "",
                ])

        section("Validated vulnerabilities", validated)
        section("Candidates (unvalidated)", candidates)
        return "\n".join(lines)


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    func: Callable[..., str]

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


def _truncate(text: str, limit: int = MAX_BODY) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 80] + f"\n...[truncated {len(text) - limit} chars]"


def _ensure_scheme(url: str) -> str:
    url = url.strip()
    if url.startswith(("http://", "https://")):
        return url
    return "https://" + url


class ToolBox:
    def __init__(
        self,
        *,
        scope: Scope,
        findings: FindingsStore,
        timeout: int = 15,
        allow_shell: bool = False,
        dry_run: bool = False,
        skills: SkillLibrary | None = None,
    ):
        self.scope = scope
        self.skills = skills
        self.findings = findings
        self.timeout = timeout
        self.allow_shell = allow_shell
        self.dry_run = dry_run
        self.requests: list[dict] = []
        self.denied: list[dict] = []
        self.finished = False
        self.summary = ""

    # -- scope gate -----------------------------------------------------

    def _check(self, url: str) -> tuple[bool, str, str]:
        full = _ensure_scheme(url)
        host = urlsplit(full).hostname or ""
        allowed, reason = self.scope.check_url(full)
        record = {"url": full, "host": host, "allowed": allowed, "reason": reason}
        if allowed:
            self.requests.append(record)
        else:
            self.denied.append(record)
        return allowed, reason, full

    # -- network tools --------------------------------------------------

    def http_request(
        self,
        method: str = "GET",
        url: str = "",
        headers: str = "",
        body: str = "",
    ) -> str:
        allowed, reason, full = self._check(url)
        if not allowed:
            return f"[scope-denied] {full} — {reason} (request skipped)"
        if self.dry_run:
            return f"[dry-run] would {method.upper()} {full}"
        hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
        if headers:
            for line in headers.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    hdrs[k.strip()] = v.strip()
        data = body.encode("utf-8") if body else None
        if data and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(full, data=data, headers=hdrs, method=method.upper())
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read(MAX_BODY * 2)
                text = raw.decode("utf-8", errors="replace")
                meta = {
                    "status": resp.status,
                    "url": resp.geturl(),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                    "length": len(raw),
                    "headers": dict(resp.headers),
                }
                return (
                    json.dumps(meta) + "\n---\n" + _truncate(text)
                )
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read(MAX_BODY).decode("utf-8", errors="replace")
            except Exception:
                pass
            return json.dumps({"status": e.code, "url": full, "error": "HTTPError"}) + "\n---\n" + _truncate(body_text)
        except urllib.error.URLError as e:
            return json.dumps({"status": None, "url": full, "error": str(e.reason)})
        except Exception as e:  # noqa: BLE001 - report anything, never crash the loop
            return json.dumps({"status": None, "url": full, "error": str(e)})

    def probe(self, url: str) -> str:
        """Lightweight GET: status, final URL, server, content-type, title."""
        allowed, reason, full = self._check(url)
        if not allowed:
            return f"[scope-denied] {full} — {reason} (probe skipped)"
        if self.dry_run:
            return f"[dry-run] would probe {full}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(full, headers={"User-Agent": DEFAULT_UA})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read(MAX_BODY * 2)
                text = raw.decode("utf-8", errors="replace")
                title = ""
                low = text.lower()
                if "<title" in low:
                    start = low.find("<title")
                    start = text.find(">", start) + 1
                    end = low.find("</title>", start)
                    if start > 0 and end > start:
                        title = text[start:end].strip()[:200]
                return json.dumps(
                    {
                        "status": resp.status,
                        "url": resp.geturl(),
                        "server": resp.headers.get("Server", ""),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "title": title,
                        "bytes": len(raw),
                    },
                    indent=2,
                )
        except urllib.error.HTTPError as e:
            return json.dumps({"status": e.code, "url": full})
        except Exception as e:  # noqa: BLE001
            return json.dumps({"status": None, "url": full, "error": str(e)})

    def dns_lookup(self, host: str) -> str:
        allowed, reason = self.scope.allows(host)
        if not allowed:
            return f"[scope-denied] {host} — {reason}"
        if self.dry_run:
            return f"[dry-run] would resolve {host}"
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = sorted({i[4][0] for i in infos})
            return json.dumps({"host": host, "addresses": addrs})
        except Exception as e:  # noqa: BLE001
            return json.dumps({"host": host, "error": str(e)})

    def run_command(self, command: str) -> str:
        if not self.allow_shell:
            return "[disabled] shell tools are off; pass --allow-shell to enable"
        low = command.lower()
        for bad in _DENY_COMMANDS:
            if bad in low:
                return f"[blocked] refusing destructive command: {command!r}"
        if self.dry_run:
            return f"[dry-run] would run: {command}"
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=120
            )
            out = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
            return _truncate(out + f"\n[exit {proc.returncode}]")
        except subprocess.TimeoutExpired:
            return "[timeout] command exceeded 120s"

    def fetch(
        self, url: str, method: str = "GET", headers: dict | None = None, body: str = ""
    ) -> tuple[dict, str]:
        """Scope-checked fetch returning ``(meta, text)``. Never raises."""
        allowed, reason, full = self._check(url)
        if not allowed:
            return {"scope_denied": True, "url": full, "reason": reason}, ""
        if self.dry_run:
            return {"dry_run": True, "url": full}, ""
        hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
        hdrs.update(headers or {})
        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(full, data=data, headers=hdrs, method=method.upper())
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read(MAX_BODY * 2)
                meta = {
                    "status": resp.status,
                    "url": resp.geturl(),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                    "length": len(raw),
                    "headers": dict(resp.headers),
                }
                return meta, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            text = ""
            try:
                text = e.read(MAX_BODY).decode("utf-8", errors="replace")
            except Exception:
                pass
            return {"status": e.code, "url": full, "error": "HTTPError"}, text
        except urllib.error.URLError as e:
            return {"status": None, "url": full, "error": str(e.reason)}, ""
        except Exception as e:  # noqa: BLE001
            return {"status": None, "url": full, "error": str(e)}, ""

    # -- skills ---------------------------------------------------------

    def list_skills(self, query: str = "") -> str:
        if self.skills is None or len(self.skills) == 0:
            return "no skills loaded"
        matches = self.skills.search(query) if query else [
            self.skills.skills[n] for n in self.skills.names()
        ]
        if not matches:
            return f"no skill matches {query!r}"
        return "\n".join(
            f"- {s.name}: {s.description[:200]}" for s in matches[:60]
        )

    def read_skill(self, name: str) -> str:
        if self.skills is None:
            return "[error] no skill library loaded"
        skill = self.skills.get(name)
        if skill is None:
            near = ", ".join(s.name for s in self.skills.search(name, limit=5))
            return f"[error] unknown skill {name!r}. close matches: {near or 'none'}"
        extra = f"\n\n(+{skill.supporting} supporting files in the skill dir)" if skill.supporting else ""
        return f"# SKILL: {skill.name}\n{skill.description}\n\n{skill.body}{extra}"

    def search_skills(self, query: str) -> str:
        if self.skills is None or len(self.skills) == 0:
            return "no skills loaded"
        matches = self.skills.search(query, limit=15)
        if not matches:
            return f"no skill matches {query!r}"
        return "\n".join(f"- {s.name}: {s.description[:240]}" for s in matches)

    # -- findings / control --------------------------------------------

    def save_finding(
        self,
        title: str,
        severity: str = "medium",
        vuln_class: str = "unknown",
        url: str = "",
        evidence: str = "",
        confidence: str = "medium",
        source: str = "",
    ) -> str:
        self.findings.add(
            Finding(
                title=title,
                severity=severity.lower(),
                vuln_class=vuln_class,
                url=url,
                evidence=evidence,
                confidence=confidence,
                status="validated",
                source=source,
            )
        )
        self.findings.save()
        return f"[saved] {severity} — {title} ({len(self.findings.items)} total)"

    def list_findings(self) -> str:
        if not self.findings.items:
            return "no findings yet"
        return "\n".join(
            f"{i}. [{f.severity}] {f.title} — {f.url}"
            for i, f in enumerate(self.findings.items, 1)
        )

    def finish(self, summary: str = "") -> str:
        self.finished = True
        self.summary = summary
        return "[finished]"

    # -- registry -------------------------------------------------------

    def tools(self) -> list[Tool]:
        return [
            Tool(
                "http_request",
                "Send an HTTP request to an in-scope URL. Returns JSON metadata "
                "(status, url, content_type, server) plus a body snippet. Use for "
                "testing injection, auth, IDOR, redirects, etc.",
                {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "description": "HTTP method (default GET)"},
                        "url": {"type": "string", "description": "Target URL"},
                        "headers": {"type": "string", "description": "Optional raw header lines"},
                        "body": {"type": "string", "description": "Optional request body"},
                    },
                    "required": ["url"],
                },
                self.http_request,
            ),
            Tool(
                "probe",
                "Quick GET of an in-scope URL: status, final URL, server, content-type, title.",
                {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
                self.probe,
            ),
            Tool(
                "dns_lookup",
                "Resolve an in-scope hostname to IP addresses.",
                {
                    "type": "object",
                    "properties": {"host": {"type": "string"}},
                    "required": ["host"],
                },
                self.dns_lookup,
            ),
            Tool(
                "save_finding",
                "Record a confirmed or likely vulnerability. Persists to findings.json "
                "and FINDINGS.md. Only save with concrete evidence.",
                {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "vuln_class": {"type": "string"},
                        "url": {"type": "string"},
                        "evidence": {"type": "string"},
                        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                        "source": {"type": "string", "description": "Scan file this came from"},
                    },
                    "required": ["title", "url", "evidence"],
                },
                self.save_finding,
            ),
            Tool(
                "list_findings",
                "List findings recorded so far.",
                {"type": "object", "properties": {}},
                self.list_findings,
            ),
            Tool(
                "run_command",
                "Run a local shell command (curl, nmap, etc.). Disabled unless "
                "--allow-shell is set. Commands are NOT scope-checked, so only use "
                "them against in-scope hosts.",
                {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
                self.run_command,
            ),
            Tool(
                "list_skills",
                "List loaded skills, optionally filtered by a query. Skills are "
                "methodology playbooks (e.g. hunt-sqli, hunt-idor, hunt-xss).",
                {
                    "type": "object",
                    "properties": {"query": {"type": "string", "description": "Optional filter"}},
                },
                self.list_skills,
            ),
            Tool(
                "search_skills",
                "Search skills by keyword (class, technology, technique) and get "
                "name + description matches.",
                {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
                self.search_skills,
            ),
            Tool(
                "read_skill",
                "Load the full methodology of a skill by name. Call this BEFORE "
                "hunting a vulnerability class so you follow the proven playbook.",
                {
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Exact skill name"}},
                    "required": ["name"],
                },
                self.read_skill,
            ),
            Tool(
                "finish",
                "Stop hunting and return a summary of what was tested and found.",
                {
                    "type": "object",
                    "properties": {"summary": {"type": "string"}},
                },
                self.finish,
            ),
        ]

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self.tools()]

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        for tool in self.tools():
            if tool.name == name:
                try:
                    return tool.func(**arguments)
                except TypeError as e:
                    return f"[error] bad arguments for {name}: {e}"
        return f"[error] unknown tool: {name}"
