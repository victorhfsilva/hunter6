"""hunter6 command-line interface.

    hunter6 triage ./scans --authorized          # validate + write FINDINGS/<sub>.md
    hunter6 triage ./scans --no-ai               # offline: candidates only
    hunter6 parse ./scans --json                 # inspect what was found
    hunter6 skills --query sqli                  # skill library
    hunter6 providers                            # AI providers

Input: a folder of custom scan-tool output (any text format).
Output: one `FINDINGS/<subdomain>.md` (+ `.json`) per subdomain, plus a root
`FINDINGS.md` index.

Skills: OpenCode skills are used by default; override with `--skills DIR`
(repeatable) or disable with `--no-skills`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, providers
from .scan import build_report
from .scope import MODES, Scope
from .skills import SkillLibrary, default_skill_roots
from .triage import run_triage


def _add_skills_args(sp) -> None:
    sp.add_argument(
        "--skills", action="append", default=[], metavar="DIR",
        help="skills folder (repeatable). Default: ./skills, "
             "~/.config/opencode/skills, ~/.agents/skills",
    )
    sp.add_argument("--no-skills", action="store_true", help="disable the skill library")


def _add_scope_args(sp) -> None:
    sp.add_argument("--scope-mode", choices=MODES, default=None,
                    help="scope mode (default: derived from scan hosts)")
    sp.add_argument("--in-scope", action="append", default=[], metavar="HOST",
                    help="restrict AI validation to this subdomain/host "
                         "(repeatable). e.g. --in-scope api.example.com")
    sp.add_argument("--scope-file", "--scope", dest="scope_file", default=None,
                    metavar="FILE",
                    help="txt file with one in-scope subdomain per line "
                         "(or a scope.yaml with in_scope/out_of_scope)")
    sp.add_argument("--exclude", action="append", default=[], metavar="HOST",
                    help="out-of-scope host/pattern (repeatable)")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunter6",
        description="Triage a folder of scan results into per-subdomain FINDINGS.",
    )
    p.add_argument("--version", action="version", version=f"hunter6 {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # -- triage ---------------------------------------------------------
    t = sub.add_parser("triage", help="parse scans, validate, write FINDINGS/<sub>.md")
    t.add_argument("scan_dir", help="folder with scan results")
    t.add_argument("--provider", default=None, help="AI provider id (default: verboo)")
    t.add_argument("--model", default=None, help="model id")
    t.add_argument("--base-url", default=None, help="override provider base URL")
    t.add_argument("--api-key", default=None, help="override provider API key")
    _add_skills_args(t)
    _add_scope_args(t)
    t.add_argument("--authorized", "-y", action="store_true",
                   help="confirm you are authorized to test the scanned hosts")
    t.add_argument("--out", default=None, help="output directory")
    t.add_argument("--max-hosts", type=int, default=25, help="max subdomains to process")
    t.add_argument("--max-candidates", type=int, default=20,
                   help="max candidates per subdomain")
    t.add_argument("--max-steps", type=int, default=12, help="max AI turns per subdomain")
    t.add_argument("--temperature", type=float, default=0.2)
    t.add_argument("--timeout", type=int, default=15, help="per-request seconds")
    t.add_argument("--ai-timeout", type=int, default=120, help="AI request seconds")
    t.add_argument("--allow-shell", action="store_true",
                   help="enable the run_command tool (NOT scope-checked)")
    t.add_argument("--dry-run", action="store_true", help="no network requests")
    t.add_argument("--no-ai", action="store_true",
                   help="offline: write candidates only, no validation")
    t.add_argument("-q", "--quiet", action="store_true")

    # -- parse ----------------------------------------------------------
    pr = sub.add_parser("parse", help="parse scans and print hosts + candidates (offline)")
    pr.add_argument("scan_dir")
    pr.add_argument("--json", action="store_true", help="machine-readable output")
    pr.add_argument("--max-files", type=int, default=5000)

    # -- scope ----------------------------------------------------------
    sc = sub.add_parser("scope", help="show the effective validation scope for a scan dir")
    sc.add_argument("scan_dir", help="folder with scan results")
    _add_scope_args(sc)

    # -- skills ---------------------------------------------------------
    sk = sub.add_parser("skills", help="list loaded skills")
    _add_skills_args(sk)
    sk.add_argument("--query", default="", help="filter by keyword")
    sk.add_argument("--full", action="store_true", help="show full descriptions")

    sub.add_parser("providers", help="list AI providers and models")
    return p


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_skills(ns) -> SkillLibrary | None:
    if getattr(ns, "no_skills", False):
        return None
    roots = default_skill_roots(getattr(ns, "skills", None) or None)
    return SkillLibrary(roots).discover()


def _build_scope(ns, scan_dir: Path) -> Scope | None:
    """Resolve the validation scope from CLI flags.

    Priority:
      1. ``--in-scope`` hosts and/or ``--scope-file`` (explicit allow-list).
         When both are given, their hosts are merged.
      2. ``--scope-mode`` (auto/strict/off) applied to the derived host set.
      3. None -> run_triage derives scope from the scanned hosts.
    """
    excludes = list(ns.exclude or [])
    explicit_hosts: list[str] = list(ns.in_scope or [])

    if ns.scope_file:
        file_scope = Scope.from_file(ns.scope_file)
        explicit_hosts.extend(file_scope.in_scope)
        # A scope file may also declare its own out-of-scope list.
        excludes.extend(file_scope.out_of_scope)

    if explicit_hosts:
        allow_sub = ns.scope_mode != "strict"
        source = "explicit"
        if ns.scope_file and ns.in_scope:
            source = f"--in-scope + {ns.scope_file}"
        elif ns.scope_file:
            source = str(ns.scope_file)
        else:
            source = "--in-scope"
        return Scope.from_hosts(
            explicit_hosts,
            allow_subdomains=allow_sub,
            out_of_scope=excludes,
            source=source,
        )

    if ns.scope_mode == "off":
        return Scope.load("", mode="off", excludes=excludes)
    if ns.scope_mode in ("auto", "strict"):
        # No explicit hosts: derive the host list from the scans, then apply
        # the requested mode (strict disables subdomain matching).
        from .scan import build_report as _build_report

        report = _build_report(scan_dir)
        hosts = [h for h in report.hosts if h != "_unknown"]
        return Scope.from_hosts(
            hosts,
            allow_subdomains=(ns.scope_mode != "strict"),
            out_of_scope=excludes,
            source=f"scans ({scan_dir})",
        )
    return None  # run_triage derives it from the scan hosts


def _authorized(ns) -> bool:
    if ns.authorized:
        return True
    if os.environ.get("HUNTER6_AUTHORIZED", "").lower() in ("1", "true", "yes", "y"):
        return True
    if sys.stdin.isatty():
        try:
            ans = input(
                "Do you have written authorization to test the hosts in these "
                "scan results? [y/N] "
            ).strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes")
    return False


def _print_providers() -> None:
    print("AI providers (default: verboo)\n")
    for pid in providers.all_ids():
        prov = providers.resolve(pid)
        star = " *" if pid == providers.DEFAULT_PROVIDER else ""
        print(f"  {pid}{star}  — {prov.display_name}  [{prov.kind}]")
        print(f"      base  : {prov.resolved_base_url()}")
        print(f"      models: {', '.join(m for m in prov.models if m) or '(set --model)'}")
        key = prov.key()
        state = "set" if key else ("not required" if not prov.requires_key else "MISSING")
        print(f"      key   : {prov.api_key_env} ({state})")
    print("\n  * = default")


def _cmd_skills(ns) -> int:
    lib = _load_skills(ns)
    if lib is None:
        print("skills disabled")
        return 0
    print(f"skill roots: {', '.join(str(r) for r in lib.roots)}")
    print(f"loaded     : {len(lib)} skill(s) from {lib.source_description()}\n")
    matches = lib.search(ns.query) if ns.query else [lib.skills[n] for n in lib.names()]
    for skill in matches:
        if ns.full:
            print(f"- {skill.name}\n    {skill.description}")
        else:
            print(f"- {skill.name}: {skill.description[:120]}")
    if not matches:
        print("(no matches)")
    return 0


def _cmd_scope(ns) -> int:
    scan_dir = Path(ns.scan_dir).expanduser().resolve()
    if not scan_dir.is_dir():
        print(f"hunter6: not a directory: {scan_dir}", file=sys.stderr)
        return 2
    scope = _build_scope(ns, scan_dir)
    if scope is None:
        report = build_report(scan_dir)
        hosts = [h for h in report.hosts if h != "_unknown"]
        scope = Scope.from_hosts(
            hosts, allow_subdomains=True, source=f"derived from scans ({scan_dir})"
        )
    print("effective validation scope\n")
    print(scope.describe())
    report = build_report(scan_dir)
    hosts = sorted(report.by_host)
    allowed = [h for h in hosts if h == "_unknown" or scope.allows(h)[0]]
    blocked = [h for h in hosts if h not in allowed]
    print(f"\nsubdomains in scans : {len(hosts)}")
    print(f"will validate       : {len(allowed)}")
    for h in allowed:
        print(f"  + {h}")
    if blocked:
        print(f"will NOT validate   : {len(blocked)} (candidates still written)")
        for h in blocked:
            print(f"  - {h}")
    return 0


def _cmd_parse(ns) -> int:
    root = Path(ns.scan_dir).expanduser().resolve()
    if not root.is_dir():
        print(f"hunter6: not a directory: {root}", file=sys.stderr)
        return 2
    report = build_report(root, max_files=ns.max_files)
    if ns.json:
        print(json.dumps(
            {
                "root": str(report.root),
                "files": report.files,
                "hosts": report.hosts,
                "candidates": report.candidate_count(),
                "by_host": {
                    h: [c.__dict__ for c in report.by_host[h]] for h in report.hosts
                },
                "skipped": report.skipped,
            },
            indent=2,
        ))
        return 0
    print(f"scan dir : {report.root}")
    print(f"files    : {report.files}")
    print(f"hosts    : {len(report.hosts)}")
    print(f"candidates: {report.candidate_count()}\n")
    for host in report.hosts:
        cands = report.by_host[host]
        print(f"- {host}  ({len(cands)} candidate(s))")
        for c in cands[:8]:
            loc = c.url or c.snippet[:80]
            print(f"    [{c.severity}] {c.vuln_type}: {loc}")
        if len(cands) > 8:
            print(f"    … and {len(cands) - 8} more")
    if report.skipped:
        print(f"\nskipped {len(report.skipped)} path(s)")
    return 0


def _cmd_triage(ns) -> int:
    scan_dir = Path(ns.scan_dir).expanduser().resolve()
    if not scan_dir.is_dir():
        print(f"hunter6: not a directory: {scan_dir}", file=sys.stderr)
        return 2

    provider = None
    ai_requested = not ns.no_ai
    if ai_requested:
        try:
            provider = providers.resolve(ns.provider, base_url=ns.base_url, api_key=ns.api_key)
        except KeyError:
            print(
                f"hunter6: unknown provider {ns.provider!r} "
                f"(known: {', '.join(providers.all_ids())})",
                file=sys.stderr,
            )
            return 2

    will_send_network = (
        ai_requested
        and provider is not None
        and (not provider.requires_key or bool(provider.key()))
        and not ns.dry_run
    )
    if will_send_network and not _authorized(ns):
        print(
            "hunter6: authorization not confirmed.\n"
            "  Validation sends real requests to the scanned hosts. Confirm with:\n"
            f"    hunter6 triage {ns.scan_dir} --authorized\n"
            "  Or run offline (candidates only):\n"
            f"    hunter6 triage {ns.scan_dir} --no-ai\n"
            "  (non-interactive runs require --authorized or HUNTER6_AUTHORIZED=1)",
            file=sys.stderr,
        )
        return 3

    scope = _build_scope(ns, scan_dir)
    skills = _load_skills(ns)
    out_dir = Path(ns.out).expanduser().resolve() if ns.out else (
        Path.cwd() / "hunter_out" / (scan_dir.name or "scans")
    )

    result = run_triage(
        scan_dir=scan_dir,
        out_dir=out_dir,
        scope=scope,
        provider=provider,
        model=ns.model or "",
        skills=skills,
        max_hosts=ns.max_hosts,
        max_candidates_per_host=ns.max_candidates,
        max_steps=ns.max_steps,
        temperature=ns.temperature,
        timeout=ns.timeout,
        ai_timeout=ns.ai_timeout,
        allow_shell=ns.allow_shell,
        dry_run=ns.dry_run,
        no_ai=ns.no_ai,
        base_url=ns.base_url,
        verbose=not ns.quiet,
    )

    print("\n=== hunter6 summary ===")
    print(f"scan dir : {result.root}")
    print(f"files    : {result.scan.files}")
    print(f"hosts    : {len(result.hosts)}")
    print(f"scope    : {', '.join(result.scope_in) or '(derived)'} [{result.scope_source}]")
    print(f"skills   : {result.skills_loaded} ({result.skills_source or 'disabled'})")
    total_valid = sum(h.validated for h in result.hosts)
    total_cand = sum(h.candidates for h in result.hosts)
    print(f"findings : {total_valid} validated / {total_cand} candidates")
    for h in result.hosts:
        ai = f" ai={h.steps}st" if h.ai_used else ""
        print(f"  - {h.host}: {h.validated} validated / {h.candidates} candidates{ai}")
    print(f"output   : {result.out_dir}")
    print(f"index    : {result.out_dir / 'FINDINGS.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = _build_parser().parse_args(argv)
    if ns.command == "providers":
        _print_providers()
        return 0
    if ns.command == "skills":
        return _cmd_skills(ns)
    if ns.command == "parse":
        return _cmd_parse(ns)
    if ns.command == "scope":
        return _cmd_scope(ns)
    if ns.command == "triage":
        return _cmd_triage(ns)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
