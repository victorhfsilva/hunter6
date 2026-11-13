"""Scan-result parsing tests (no network)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6.scan import (  # noqa: E402
    build_report,
    classify_text,
    extract_hosts,
    host_hint_from_path,
    looks_like_host,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_looks_like_host():
    assert looks_like_host("api.example.com")
    assert not looks_like_host("app.js")
    assert not looks_like_host("localhost")
    assert not looks_like_host("style.css")


def test_extract_hosts_from_urls_and_text():
    hosts = extract_hosts(
        "see https://api.example.com/v1 and www.example.org, skip app.js"
    )
    assert "api.example.com" in hosts
    assert "www.example.org" in hosts
    assert all(not h.endswith(".js") for h in hosts)


def test_host_hint_from_path(tmp_path: Path):
    p = tmp_path / "api.example.com" / "out.txt"
    p.parent.mkdir()
    p.write_text("x", encoding="utf-8")
    assert host_hint_from_path(p, tmp_path) == "api.example.com"

    q = tmp_path / "nuclei_shop.example.com.json"
    q.write_text("[]", encoding="utf-8")
    assert host_hint_from_path(q, tmp_path) == "shop.example.com"


def test_classify_text():
    assert classify_text("[CRITICAL] Remote Code Execution at /x")[0] == "RCE"
    assert classify_text("[HIGH] Reflected XSS on /search")[0] == "XSS"
    assert classify_text("nothing interesting here") is None


def test_jsonl_report_groups_by_host(tmp_path: Path):
    _write(
        tmp_path / "api.example.com" / "nuclei.jsonl",
        '{"template-id":"sqli","matched-at":"https://api.example.com/u?id=1",'
        '"info":{"name":"SQL Injection","severity":"high","description":"id is injectable"}}\n'
        '{"template-id":"xss","matched-at":"https://www.example.com/s?q=1",'
        '"info":{"name":"XSS","severity":"medium"}}\n',
    )
    report = build_report(tmp_path)
    assert report.files == 1
    assert "api.example.com" in report.by_host
    assert "www.example.com" in report.by_host
    sqli = [c for c in report.by_host["api.example.com"] if c.vuln_type == "SQL Injection"]
    assert sqli and sqli[0].severity == "high"
    assert "injectable" in sqli[0].snippet


def test_json_array_container(tmp_path: Path):
    _write(
        tmp_path / "results.json",
        json.dumps({
            "results": [
                {"host": "shop.example.com", "url": "https://shop.example.com/o/2",
                 "type": "IDOR", "severity": "high", "detail": "other user order"},
            ]
        }),
    )
    report = build_report(tmp_path)
    assert "shop.example.com" in report.by_host
    assert report.by_host["shop.example.com"][0].vuln_type == "IDOR"


def test_plaintext_report_and_content_hosts(tmp_path: Path):
    _write(
        tmp_path / "notes.txt",
        "blog.example.com has CSRF on /comment (medium)\n"
        "cdn.example.com: subdomain takeover via dangling CNAME (high)\n"
        "clean line without issues\n",
    )
    report = build_report(tmp_path)
    assert "blog.example.com" in report.by_host
    assert "cdn.example.com" in report.by_host
    assert report.by_host["blog.example.com"][0].vuln_type == "CSRF"
    assert report.by_host["cdn.example.com"][0].vuln_type == "Subdomain Takeover"


def test_duplicate_candidates_deduped(tmp_path: Path):
    line = '{"host":"a.example.com","type":"XSS","severity":"high","detail":"x"}\n'
    _write(tmp_path / "a.jsonl", line + line)
    report = build_report(tmp_path)
    assert len(report.by_host["a.example.com"]) == 1


def test_skips_binary_and_large(tmp_path: Path):
    _write(tmp_path / "ok.txt", "x.example.com XSS (medium)")
    (tmp_path / "img.png").write_bytes(b"\x89PNG")
    report = build_report(tmp_path)
    assert report.files == 1
    assert any("img.png" in s for s in report.skipped)


def test_unknown_host_fallback(tmp_path: Path):
    _write(tmp_path / "misc.txt", "[high] SQL injection somewhere")
    report = build_report(tmp_path)
    assert "_unknown" in report.by_host
