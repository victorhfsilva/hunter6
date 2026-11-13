"""Triage tests: offline per-host FINDINGS writing + validated dedupe."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6.scope import Scope  # noqa: E402
from hunter6.tools import Finding, FindingsStore  # noqa: E402
from hunter6.triage import _dedupe_validated, _safe_stem, run_triage  # noqa: E402


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_safe_stem():
    assert _safe_stem("api.example.com") == "api.example.com"
    assert _safe_stem("bad/host name") == "bad_host_name"


def test_offline_triage_writes_one_file_per_host(tmp_path: Path):
    scans = tmp_path / "scans"
    _write(
        scans / "api.example.com" / "out.jsonl",
        '{"matched-at":"https://api.example.com/u?id=1",'
        '"info":{"name":"SQL Injection","severity":"high","description":"id injectable"}}\n',
    )
    _write(
        scans / "www.example.com" / "out.txt",
        "[HIGH] Reflected XSS on https://www.example.com/search?q=1\n",
    )
    out = tmp_path / "out"
    result = run_triage(
        scan_dir=scans,
        out_dir=out,
        scope=None,
        provider=None,
        no_ai=True,
        verbose=False,
    )
    assert {h.host for h in result.hosts} == {"api.example.com", "www.example.com"}
    assert (out / "FINDINGS" / "api.example.com.md").exists()
    assert (out / "FINDINGS" / "www.example.com.md").exists()
    assert (out / "FINDINGS.md").exists()

    md = (out / "FINDINGS" / "api.example.com.md").read_text()
    assert "Candidates (unvalidated)" in md
    assert "SQL Injection" in md
    assert "Validated: 0" in md

    data = json.loads((out / "FINDINGS" / "api.example.com.json").read_text())
    assert data[0]["status"] == "candidate"


def test_scope_derived_from_scans(tmp_path: Path):
    scans = tmp_path / "scans"
    _write(scans / "a.example.com" / "r.txt", "a.example.com XSS (medium)\n")
    result = run_triage(
        scan_dir=scans, out_dir=tmp_path / "o", scope=None,
        provider=None, no_ai=True, verbose=False,
    )
    assert result.hosts[0].host == "a.example.com"


def test_explicit_scope_respected(tmp_path: Path):
    scans = tmp_path / "scans"
    _write(scans / "a.example.com" / "r.txt", "a.example.com XSS (medium)\n")
    scope = Scope.from_target("a.example.com")
    scope.out_of_scope.append("a.example.com")
    result = run_triage(
        scan_dir=scans, out_dir=tmp_path / "o", scope=scope,
        provider=None, no_ai=True, verbose=False,
    )
    assert result.hosts[0].host == "a.example.com"  # still reported, just not tested


def test_dedupe_validated_by_url(tmp_path: Path):
    store = FindingsStore(out_dir=tmp_path, stem="host")
    store.add(Finding(
        title="IDOR at /api/user?id=1", severity="high", vuln_class="IDOR",
        url="https://h.test/api/user?id=1", evidence="candidate", status="candidate",
    ))
    store.add(Finding(
        title="Unauthenticated IDOR on /api/user", severity="high",
        vuln_class="IDOR / Broken Object Level Authorization",
        url="https://h.test/api/user?id=2", evidence="proved", status="validated",
    ))
    store.add(Finding(
        title="XSS at /search", severity="medium", vuln_class="XSS",
        url="https://h.test/search?q=1", evidence="candidate", status="candidate",
    ))
    _dedupe_validated(store)
    titles = [f.title for f in store.items]
    assert "IDOR at /api/user?id=1" not in titles          # covered by validated
    assert "Unauthenticated IDOR on /api/user" in titles    # validated kept
    assert "XSS at /search" in titles                       # unrelated kept


def test_index_lists_hosts(tmp_path: Path):
    scans = tmp_path / "scans"
    _write(scans / "a.example.com" / "r.txt", "a.example.com XSS (medium)\n")
    _write(scans / "b.example.com" / "r.txt", "b.example.com SSRF (high)\n")
    out = tmp_path / "o"
    run_triage(scan_dir=scans, out_dir=out, scope=None, provider=None,
               no_ai=True, verbose=False)
    index = (out / "FINDINGS.md").read_text()
    assert "a.example.com" in index
    assert "b.example.com" in index
    assert "FINDINGS/a.example.com.md" in index


def test_explicit_scope_restricts_ai_validation(tmp_path: Path, monkeypatch):
    """Only in-scope hosts reach the AI validator; others are candidates-only."""
    scans = tmp_path / "scans"
    _write(scans / "api.example.com" / "r.txt", "api.example.com XSS (medium)\n")
    _write(scans / "www.example.com" / "r.txt", "www.example.com SSRF (high)\n")

    called: list[str] = []

    def fake_validate(**kw):
        called.append(kw["host"])
        return 1, {}, "fake"

    monkeypatch.setattr("hunter6.triage._ai_validate_host", fake_validate)

    from hunter6.providers import Provider

    dummy = Provider(
        id="dummy", display_name="Dummy", kind="openai",
        base_url="http://x", models=(), default_model="m",
        api_key_env="DUMMY_KEY", base_url_env="DUMMY_BASE", model_env="DUMMY_MODEL",
        requires_key=False,
    )
    scope = Scope.from_hosts(["api.example.com"], source="--in-scope")
    out = tmp_path / "o"
    result = run_triage(
        scan_dir=scans, out_dir=out, scope=scope, provider=dummy,
        no_ai=False, verbose=False,
    )
    assert called == ["api.example.com"]          # only in-scope validated
    assert result.scope_in == ["api.example.com"]
    # Both hosts still get a findings file (candidates for the out-of-scope one).
    assert (out / "FINDINGS" / "api.example.com.md").exists()
    assert (out / "FINDINGS" / "www.example.com.md").exists()
    by_host = {h.host: h for h in result.hosts}
    assert by_host["api.example.com"].ai_used is True
    assert by_host["www.example.com"].ai_used is False


def test_scope_file_restricts_validation(tmp_path: Path, monkeypatch):
    scans = tmp_path / "scans"
    _write(scans / "a.example.com" / "r.txt", "a.example.com XSS (medium)\n")
    _write(scans / "b.example.com" / "r.txt", "b.example.com SSRF (high)\n")

    called: list[str] = []
    monkeypatch.setattr(
        "hunter6.triage._ai_validate_host",
        lambda **kw: (called.append(kw["host"]) or (0, {}, "")),
    )

    from hunter6.providers import Provider

    dummy = Provider(
        id="dummy", display_name="Dummy", kind="openai",
        base_url="http://x", models=(), default_model="m",
        api_key_env="DUMMY_KEY", base_url_env="DUMMY_BASE", model_env="DUMMY_MODEL",
        requires_key=False,
    )
    scope = Scope.from_file(_write_scope(tmp_path, "b.example.com\n"))
    run_triage(
        scan_dir=scans, out_dir=tmp_path / "o", scope=scope,
        provider=dummy, no_ai=False, verbose=False,
    )
    assert called == ["b.example.com"]


def _write_scope(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "scope.txt"
    p.write_text(text, encoding="utf-8")
    return p
