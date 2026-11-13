"""Parse a folder of custom scan-tool output into per-subdomain candidates.

Custom tools have no fixed schema, so this module is deliberately tolerant:

* Every regular text file under the input root is read (recursively).
* Each file is attributed to a **subdomain** using, in order:
  1. a host-like parent directory name (``scans/api.example.com/out.txt``);
  2. a host-like filename component (``nuclei_api.example.com.json``);
  3. the hosts found inside the content itself.
* Candidate vulnerabilities are extracted from JSON / JSONL / XML-ish / plain
  text using keyword + field heuristics.

The result is a :class:`ScanReport` grouped by host, which the triage stage
then validates (optionally with AI) and writes out as
``FINDINGS/<subdomain>.md``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

MAX_FILE_BYTES = 2_000_000
TEXT_SUFFIXES = {
    ".txt", ".json", ".jsonl", ".ndjson", ".xml", ".csv", ".tsv", ".log",
    ".md", ".yaml", ".yml", ".html", ".htm", ".out", ".lst", ".list", "",
}

HOST_RE = re.compile(
    r"(?<![\w.\-])("
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}"
    r")(?![\w.\-])"
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
_NON_HOST_TLDS = {
    "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
    "ttf", "map", "php", "html", "htm", "asp", "aspx", "jsp", "json", "xml",
}
_SEVERITIES = ("critical", "high", "medium", "low", "info", "informational")

# keyword -> (vuln class, default severity)
_VULN_KEYWORDS: list[tuple[str, str, str]] = [
    ("remote code execution", "RCE", "critical"),
    ("command injection", "Command Injection", "critical"),
    ("rce", "RCE", "critical"),
    ("sql injection", "SQL Injection", "high"),
    ("sqli", "SQL Injection", "high"),
    ("nosql", "NoSQL Injection", "high"),
    ("cross-site scripting", "XSS", "medium"),
    ("cross site scripting", "XSS", "medium"),
    ("xss", "XSS", "medium"),
    ("ssrf", "SSRF", "high"),
    ("server-side request forgery", "SSRF", "high"),
    ("xxe", "XXE", "high"),
    ("xml external entity", "XXE", "high"),
    ("path traversal", "Path Traversal", "high"),
    ("directory traversal", "Path Traversal", "high"),
    ("lfi", "LFI", "high"),
    ("rfi", "RFI", "high"),
    ("insecure deserialization", "Deserialization", "critical"),
    ("deserialization", "Deserialization", "high"),
    ("idor", "IDOR", "high"),
    ("bola", "IDOR", "high"),
    ("broken access control", "Access Control", "high"),
    ("privilege escalation", "Privilege Escalation", "high"),
    ("authentication bypass", "Auth Bypass", "critical"),
    ("auth bypass", "Auth Bypass", "critical"),
    ("default credential", "Default Credentials", "high"),
    ("weak password", "Weak Credentials", "high"),
    ("subdomain takeover", "Subdomain Takeover", "high"),
    ("dangling", "Subdomain Takeover", "high"),
    ("open redirect", "Open Redirect", "low"),
    ("csrf", "CSRF", "medium"),
    ("cors", "CORS Misconfig", "medium"),
    ("prototype pollution", "Prototype Pollution", "high"),
    ("ssti", "SSTI", "critical"),
    ("template injection", "SSTI", "high"),
    ("log4shell", "Log4Shell", "critical"),
    ("cve-", "Known CVE", "high"),
    ("exposed", "Information Disclosure", "medium"),
    ("information disclosure", "Information Disclosure", "medium"),
    ("sensitive data", "Information Disclosure", "medium"),
    ("api key", "Secret Exposure", "high"),
    ("secret", "Secret Exposure", "high"),
    ("credential", "Secret Exposure", "high"),
    ("misconfig", "Misconfiguration", "medium"),
    ("misconfiguration", "Misconfiguration", "medium"),
    ("vulnerab", "Vulnerability", "medium"),
    ("takeover", "Subdomain Takeover", "high"),
]


@dataclass
class Candidate:
    host: str
    vuln_type: str
    severity: str
    source: str
    snippet: str
    url: str = ""
    line: int | None = None
    raw: str = ""

    def key(self) -> tuple:
        return (self.host, self.vuln_type, (self.url or self.snippet)[:120])


@dataclass
class ScanReport:
    root: Path
    files: int = 0
    hosts: list[str] = field(default_factory=list)
    by_host: dict[str, list[Candidate]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    files_by_host: dict[str, list[str]] = field(default_factory=dict)

    def candidate_count(self) -> int:
        return sum(len(v) for v in self.by_host.values())


# ---------------------------------------------------------------------------
# host helpers
# ---------------------------------------------------------------------------

def looks_like_host(value: str) -> bool:
    value = (value or "").strip().lower().strip(".")
    if not value or "." not in value:
        return False
    m = HOST_RE.fullmatch(value)
    if not m:
        return False
    tld = value.rsplit(".", 1)[-1]
    return tld not in _NON_HOST_TLDS


def extract_hosts(text: str) -> list[str]:
    found: list[str] = []
    for url in URL_RE.findall(text):
        host = urlsplit(url).hostname
        if host and looks_like_host(host):
            found.append(host.lower())
    for raw in HOST_RE.findall(text):
        host = raw.strip(".").lower()
        if looks_like_host(host):
            found.append(host)
    return found


def host_hint_from_path(path: Path, root: Path) -> str | None:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    # nearest directory component first, then the filename stem
    for part in reversed(rel.parts[:-1]):
        if looks_like_host(part):
            return part.lower()
    # Filename stems often join a tool name and the host with '_' or '-'
    # (e.g. ``nuclei_shop.example.com.json``). Test each token.
    for token in re.split(r"[^A-Za-z0-9.\-]+", path.stem):
        if looks_like_host(token):
            return token.lower()
    for host in extract_hosts(path.stem):
        return host
    return None


# ---------------------------------------------------------------------------
# candidate classification
# ---------------------------------------------------------------------------

def _normalize_severity(text: str) -> str | None:
    low = text.lower()
    for sev in _SEVERITIES:
        if re.search(rf"(?<![\w.]){sev}(?![\w.])", low):
            return "info" if sev == "informational" else sev
    return None


def classify_text(text: str) -> tuple[str, str] | None:
    low = text.lower()
    for kw, cls, sev in _VULN_KEYWORDS:
        if kw in low:
            found = _normalize_severity(text)
            return cls, found or sev
    return None


# ---------------------------------------------------------------------------
# file reading
# ---------------------------------------------------------------------------

def read_scan_files(root: Path, max_files: int = 5000) -> tuple[list[tuple[Path, str]], list[str]]:
    files: list[tuple[Path, str]] = []
    skipped: list[str] = []
    if not root.is_dir():
        return files, [str(root)]
    for path in sorted(root.rglob("*")):
        if len(files) >= max_files:
            skipped.append(f"(file cap {max_files} reached)")
            break
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            skipped.append(str(path))
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append(f"{path} (too large)")
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(f"{path} (unreadable)")
            continue
        files.append((path, text))
    return files, skipped


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

def _records_from_doc(node):
    """Yield record dicts from a parsed JSON document (no deep recursion)."""
    if isinstance(node, list):
        for el in node:
            if isinstance(el, dict):
                yield el
        return
    if isinstance(node, dict):
        for key in ("results", "findings", "items", "data", "vulnerabilities", "issues"):
            if isinstance(node.get(key), list):
                for el in node[key]:
                    if isinstance(el, dict):
                        yield el
                return
        yield node


def _json_records(text: str):
    """Yield record dicts from a JSON doc or JSONL, tolerant of trailing junk."""
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if data is not None:
            yield from _records_from_doc(data)
            return
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line[0] not in "[{":
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        yield from _records_from_doc(obj)


_HOST_KEYS = ("matched-at", "matched_at", "url", "host", "target", "endpoint",
              "asset", "domain", "fqdn", "uri")
_TYPE_KEYS = ("template-id", "template_id", "template", "type", "name", "title",
              "vuln", "check", "category", "plugin", "rule", "id")
_SEV_KEYS = ("severity", "risk", "level", "score")
_EVIDENCE_KEYS = ("description", "detail", "details", "proof", "evidence",
                  "output", "extracted-results", "matcher-name", "matched-at",
                  "info", "curl-command", "request", "response")


def _first(d: dict, keys) -> str:
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            v = d[k]
            if isinstance(v, dict):
                for kk in _SEV_KEYS:
                    if kk in v:
                        return str(v[kk])
                return json.dumps(v)[:300]
            if isinstance(v, list):
                return ", ".join(str(x) for x in v[:5])
            return str(v)
    return ""


def candidates_from_json(text: str, source: str, host_hint: str | None) -> list[Candidate]:
    out: list[Candidate] = []
    seen: set[tuple] = set()
    for obj in _json_records(text):
        if not isinstance(obj, dict):
            continue
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        merged = {**info, **obj}  # top-level wins, info fills gaps

        host_field = _first(merged, _HOST_KEYS)
        url = ""
        if host_field.startswith("http"):
            url = host_field
            host = urlsplit(host_field).hostname or ""
        else:
            hosts = extract_hosts(host_field) or extract_hosts(json.dumps(merged)[:600])
            host = hosts[0] if hosts else ""
        host = (host or host_hint or "").lower()

        signal_text = " ".join(str(merged.get(k, "")) for k in _TYPE_KEYS + _SEV_KEYS)
        cls = classify_text(signal_text)
        sev_field = _normalize_severity(_first(merged, _SEV_KEYS))
        if cls is None and sev_field is None:
            continue
        vuln_type, default_sev = cls if cls else ("Finding", "medium")
        severity = sev_field or default_sev
        evidence = _first(merged, _EVIDENCE_KEYS) or json.dumps(merged)[:400]

        cand = Candidate(
            host=host or "_unknown",
            vuln_type=vuln_type,
            severity=severity,
            source=source,
            snippet=evidence[:600],
            url=url,
            raw=json.dumps(merged)[:800],
        )
        key = (cand.host, cand.vuln_type, cand.url or cand.snippet[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(cand)
    return out


def candidates_from_text(text: str, source: str, host_hint: str | None) -> list[Candidate]:
    out: list[Candidate] = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or len(line) > 2000:
            continue
        cls = classify_text(line)
        if cls is None:
            continue
        hosts = extract_hosts(line)
        host = (hosts[0] if hosts else (host_hint or "_unknown")).lower()
        url = ""
        um = URL_RE.search(line)
        if um:
            url = um.group(0)
        out.append(
            Candidate(
                host=host or "_unknown",
                vuln_type=cls[0],
                severity=cls[1],
                source=source,
                snippet=line[:600],
                url=url,
                line=i,
                raw=line[:800],
            )
        )
    return out


def build_report(root: Path, max_files: int = 5000) -> ScanReport:
    report = ScanReport(root=root)
    files, skipped = read_scan_files(root, max_files=max_files)
    report.skipped = skipped
    report.files = len(files)
    for path, text in files:
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        hint = host_hint_from_path(path, root)
        is_json = path.suffix.lower() in (".json", ".jsonl", ".ndjson") or text.lstrip()[:1] in "[{"
        cands = (candidates_from_json if is_json else candidates_from_text)(text, rel, hint)
        if not cands:
            # fall back to text extraction for JSON-looking files that yielded nothing
            if is_json:
                cands = candidates_from_text(text, rel, hint)
        for c in cands:
            report.by_host.setdefault(c.host, [])
            if c.key() not in {x.key() for x in report.by_host[c.host]}:
                report.by_host[c.host].append(c)
        report.files_by_host.setdefault(hint or "_unknown", [])
        if rel not in report.files_by_host[hint or "_unknown"]:
            report.files_by_host[hint or "_unknown"].append(rel)
    report.hosts = sorted(report.by_host)
    return report
