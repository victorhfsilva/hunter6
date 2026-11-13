"""Triage orchestration: scan folder -> per-subdomain FINDINGS.

Pipeline
--------
1. ``scan.build_report`` parses every file and groups candidates by host.
2. Deterministic pass writes ``FINDINGS/<host>.md`` with every candidate marked
   ``candidate`` (unvalidated) — always, even offline.
3. Optional AI pass, **per subdomain**, validates candidates with scope-enforced
   network tools and saves proven findings as ``validated``.
4. A root ``FINDINGS.md`` index summarizes all subdomains.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import client
from .prompts import build_system_prompt, build_user_prompt
from .providers import Provider
from .scan import Candidate, ScanReport, build_report
from .scope import Scope
from .skills import SkillLibrary
from .tools import Finding, FindingsStore, ToolBox


@dataclass
class HostResult:
    host: str
    candidates: int = 0
    validated: int = 0
    ai_used: bool = False
    steps: int = 0
    usage: dict = field(default_factory=dict)
    summary: str = ""


@dataclass
class TriageResult:
    root: Path
    out_dir: Path
    scan: ScanReport
    hosts: list[HostResult] = field(default_factory=list)
    skills_loaded: int = 0
    skills_source: str = ""
    requests: int = 0
    denied: int = 0
    scope_in: list = field(default_factory=list)
    scope_source: str = ""


def _safe_stem(host: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", host.strip()) or "_unknown"
    return stem.strip("._") or "_unknown"


def _candidate_payload(c: Candidate) -> dict:
    return {
        "type": c.vuln_type,
        "severity": c.severity,
        "url": c.url,
        "snippet": c.snippet,
        "source": c.source,
        "line": c.line,
    }


def _candidate_findings(cands: list[Candidate]) -> list[Finding]:
    out = []
    for c in cands:
        title = c.vuln_type
        if c.url:
            title = f"{c.vuln_type} at {c.url}"
        out.append(
            Finding(
                title=title,
                severity=c.severity,
                vuln_class=c.vuln_type,
                url=c.url,
                evidence=c.snippet or c.raw,
                confidence="low",
                status="candidate",
                source=c.source,
            )
        )
    return out


def _url_key(url: str) -> str:
    """Scheme + host + path, ignoring query/fragment (id varies between tests)."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return ""
    if not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path.lower().rstrip('/')}"


def _dedupe_validated(store: FindingsStore) -> None:
    """Drop candidates that a validated finding already covers.

    Matching is URL-based (scheme+host+path) with a class-token check, so an
    AI that saved ``?id=2`` still suppresses the ``?id=1`` candidate.
    """
    validated = [f for f in store.items if f.status == "validated"]

    def norm(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").lower()).strip()

    v_by_url: dict[str, list[str]] = {}
    for f in validated:
        key = _url_key(f.url)
        if key:
            v_by_url.setdefault(key, []).append(norm(f.vuln_class))
    v_titles = {norm(f.title) for f in validated}

    kept: list[Finding] = []
    for f in store.items:
        if f.status == "validated":
            kept.append(f)
            continue
        if norm(f.title) in v_titles:
            continue
        key = _url_key(f.url)
        if key and key in v_by_url:
            cls = norm(f.vuln_class)
            classes = v_by_url[key]
            if any(cls in c or c in cls or cls.split(" ")[0] in c for c in classes):
                continue
        kept.append(f)
    store.items = kept


def _ai_validate_host(
    *,
    host: str,
    candidates: list[Candidate],
    store: FindingsStore,
    scope: Scope,
    skills: SkillLibrary | None,
    provider: Provider,
    model: str,
    max_steps: int,
    temperature: float,
    timeout: int,
    ai_timeout: int,
    allow_shell: bool,
    dry_run: bool,
    base_url: str | None,
    verbose: bool,
) -> tuple[int, dict, str]:
    toolbox = ToolBox(
        scope=scope,
        findings=store,
        timeout=timeout,
        allow_shell=allow_shell,
        dry_run=dry_run,
        skills=skills,
    )
    payload = [_candidate_payload(c) for c in candidates]
    messages: list[dict] = [
        {"role": "system", "content": build_system_prompt(scope, skills)},
        {"role": "user", "content": build_user_prompt(host, payload)},
    ]
    tools = toolbox.schemas()
    usage_total: dict = {}
    step = 0
    summary = ""
    for step in range(1, max_steps + 1):
        try:
            res = client.chat(
                provider,
                model,
                messages,
                tools=tools,
                temperature=temperature,
                timeout=ai_timeout,
                base_url=base_url,
            )
        except client.ProviderError as e:
            print(f"[ai:{host}] provider error: {e}")
            if e.body:
                print(f"[ai:{host}] {e.body[:400]}")
            break
        for k, v in (res.usage or {}).items():
            if isinstance(v, int):
                usage_total[k] = usage_total.get(k, 0) + v
        if res.content and verbose:
            print(f"\n[ai:{host}] {res.content.strip()[:1200]}")
        if not res.tool_calls:
            summary = res.content
            break
        messages.append(
            {"role": "assistant", "content": res.content, "tool_calls": res.tool_calls}
        )
        for call in res.tool_calls:
            out = toolbox.dispatch(call["name"], call.get("arguments") or {})
            if verbose:
                preview = json.dumps(call.get("arguments") or {}, ensure_ascii=False)
                if len(preview) > 240:
                    preview = preview[:240] + "..."
                print(f"  [{host}] -> {call['name']} {preview}")
                shown = out if len(out) <= 900 else out[:900] + "...[truncated]"
                print(f"      {shown}")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "name": call["name"],
                    "content": out,
                }
            )
        if toolbox.finished:
            summary = toolbox.summary
            break
    else:
        summary = "(max steps reached)"
    return step, usage_total, summary


def run_triage(
    *,
    scan_dir: Path,
    out_dir: Path,
    scope: Scope | None,
    provider: Provider | None,
    model: str = "",
    skills: SkillLibrary | None = None,
    max_hosts: int = 25,
    max_candidates_per_host: int = 20,
    max_steps: int = 12,
    temperature: float = 0.2,
    timeout: int = 15,
    ai_timeout: int = 120,
    allow_shell: bool = False,
    dry_run: bool = False,
    no_ai: bool = False,
    base_url: str | None = None,
    verbose: bool = True,
) -> TriageResult:
    scan_dir = scan_dir.expanduser().resolve()
    report = build_report(scan_dir)
    findings_dir = out_dir / "FINDINGS"
    findings_dir.mkdir(parents=True, exist_ok=True)

    if scope is None:
        hosts = [h for h in report.hosts if h != "_unknown"] or ["_unknown"]
        scope = Scope(
            in_scope=sorted(hosts),
            allow_subdomains=True,
            mode="file",
            authorized=True,
            source=f"derived from scans ({scan_dir})",
        )

    result = TriageResult(
        root=scan_dir,
        out_dir=out_dir,
        scan=report,
        skills_loaded=len(skills) if skills is not None else 0,
        skills_source=skills.source_description() if skills is not None else "",
        scope_in=list(scope.in_scope),
        scope_source=scope.source,
    )

    if verbose:
        print(f"[scan] {report.files} file(s), {len(report.hosts)} host(s), "
              f"{report.candidate_count()} candidate(s)")
        print(f"[scope] in-scope: {', '.join(scope.in_scope) or '(none)'}")
        if skills is not None:
            print(f"[skills] {len(skills)} loaded from {skills.source_description()}")

    ai_active = (
        not no_ai
        and provider is not None
        and (not provider.requires_key or bool(provider.key()))
    )
    if not no_ai and provider is not None and not ai_active and verbose:
        print(f"[ai] skipped: no key for {provider.id} (set {provider.api_key_env})")

    hosts_sorted = sorted(report.by_host)

    def _in_validation_scope(h: str) -> bool:
        if h == "_unknown":
            return True
        return scope.allows(h)[0]

    in_scope_hosts = [h for h in hosts_sorted if _in_validation_scope(h)]
    out_scope_hosts = [h for h in hosts_sorted if not _in_validation_scope(h)]

    if verbose:
        print(
            f"[scope] validation targets: {len(in_scope_hosts)} in scope, "
            f"{len(out_scope_hosts)} out of scope (candidates still written)"
        )

    for host in in_scope_hosts[:max_hosts]:
        cands = report.by_host.get(host, [])[:max_candidates_per_host]
        store = FindingsStore(out_dir=findings_dir, stem=_safe_stem(host))
        for f in _candidate_findings(cands):
            store.add(f)
        store.save()

        hr = HostResult(host=host, candidates=len(cands))
        if ai_active:
            if verbose:
                print(f"\n[host] {host} — {len(cands)} candidate(s), validating…")
            steps, usage, summary = _ai_validate_host(
                host=host,
                candidates=cands,
                store=store,
                scope=scope,
                skills=skills,
                provider=provider,  # type: ignore[arg-type]
                model=model or provider.model(),  # type: ignore[union-attr]
                max_steps=max_steps,
                temperature=temperature,
                timeout=timeout,
                ai_timeout=ai_timeout,
                allow_shell=allow_shell,
                dry_run=dry_run,
                base_url=base_url,
                verbose=verbose,
            )
            hr.ai_used = True
            hr.steps = steps
            hr.usage = usage
            hr.summary = summary
            _dedupe_validated(store)
            store.save()

        hr.validated = sum(1 for f in store.items if f.status == "validated")
        result.hosts.append(hr)

    # Hosts beyond --max-hosts: candidates only.
    for host in in_scope_hosts[max_hosts:]:
        cands = report.by_host.get(host, [])[:max_candidates_per_host]
        store = FindingsStore(out_dir=findings_dir, stem=_safe_stem(host))
        for f in _candidate_findings(cands):
            store.add(f)
        store.save()
        result.hosts.append(HostResult(host=host, candidates=len(cands)))

    # Out-of-scope hosts: write candidates only, never validate.
    for host in out_scope_hosts:
        cands = report.by_host.get(host, [])[:max_candidates_per_host]
        store = FindingsStore(out_dir=findings_dir, stem=_safe_stem(host))
        for f in _candidate_findings(cands):
            store.add(f)
        store.save()
        result.hosts.append(HostResult(host=host, candidates=len(cands)))

    _write_index(out_dir / "FINDINGS.md", result)
    return result


def _write_index(path: Path, result: TriageResult) -> None:
    lines = [
        "# FINDINGS — index",
        "",
        f"- scan dir : `{result.root}`",
        f"- files    : {result.scan.files}",
        f"- hosts    : {len(result.hosts)}",
        f"- scope    : {', '.join(result.scope_in) or '(derived)'} "
        f"[{result.scope_source}]",
        f"- skills   : {result.skills_loaded} ({result.skills_source or 'disabled'})",
        "",
        "| Subdomain | Candidates | Validated | AI |",
        "|---|---|---|---|",
    ]
    for h in result.hosts:
        ai = f"{h.steps} steps" if h.ai_used else "—"
        lines.append(f"| [{h.host}](FINDINGS/{_safe_stem(h.host)}.md) | {h.candidates} | {h.validated} | {ai} |")
    lines += ["", "Per-subdomain reports live in `FINDINGS/<subdomain>.md`.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
