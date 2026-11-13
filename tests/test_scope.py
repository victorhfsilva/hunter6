"""Scope model tests — the heart of the scope-limits fix."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6.scope import Scope, normalize_host  # noqa: E402


def test_normalize_host_variants():
    assert normalize_host("https://api.example.com/v1?x=1") == "api.example.com"
    assert normalize_host("example.com:8443") == "example.com"
    assert normalize_host("user@Example.COM") == "example.com"
    assert normalize_host("http://[::1]:8080/") == "::1"


def test_auto_allows_apex_and_subdomains():
    s = Scope.from_target("example.com")
    assert s.allows("example.com")[0]
    assert s.allows("api.example.com")[0]
    assert s.allows("https://deep.api.example.com/x")[0]
    assert not s.allows("evil.com")[0]


def test_strict_denies_subdomains():
    s = Scope.from_target("example.com", mode="strict")
    assert s.allows("example.com")[0]
    assert not s.allows("api.example.com")[0]


def test_out_of_scope_wins():
    s = Scope.from_target("example.com")
    s.out_of_scope.append("admin.example.com")
    assert not s.allows("admin.example.com")[0]
    assert s.allows("api.example.com")[0]


def test_wildcard_pattern():
    s = Scope.from_target("example.com")
    s.in_scope.append("*.corp.example.com")
    assert s.allows("a.corp.example.com")[0]
    assert s.allows("corp.example.com")[0]


def test_excludes_are_normalized():
    s = Scope.load("example.com", excludes=["https://legacy.example.com/path"])
    assert not s.allows("legacy.example.com")[0]


def test_off_mode_allows_everything():
    s = Scope.load("example.com", mode="off")
    assert s.allows("anything.test")[0]
    assert s.notes


def test_scope_file_yaml(tmp_path: Path):
    f = tmp_path / "scope.yaml"
    f.write_text(
        "in_scope:\n  - example.com\n  - '*.api.example.com'\n"
        "out_of_scope:\n  - legacy.example.com\n"
    )
    s = Scope.load("example.com", scope_file=str(f))
    assert s.mode == "file"
    assert s.authorized
    assert s.allows("api.example.com")[0]
    assert not s.allows("legacy.example.com")[0]


def test_scope_file_text(tmp_path: Path):
    f = tmp_path / "scope.txt"
    f.write_text("# program\nexample.com\napi.example.com\n\n# Out of Scope\nlegacy.example.com\n")
    s = Scope.load("example.com", scope_file=str(f))
    assert s.allows("api.example.com")[0]
    assert not s.allows("legacy.example.com")[0]


def test_ip_target():
    s = Scope.from_target("127.0.0.1:8765")
    assert s.allows("127.0.0.1")[0]
    assert s.allows("http://127.0.0.1:8765/")[0]


def test_empty_host_denied():
    s = Scope.from_target("example.com")
    assert not s.allows("")[0]


def test_from_hosts_normalizes_urls_ports_wildcards():
    s = Scope.from_hosts(
        ["https://api.example.com:8443/x", "*.corp.example.com", "Example.COM"],
        out_of_scope=["legacy.example.com"],
    )
    assert s.allows("api.example.com")[0]
    assert s.allows("a.corp.example.com")[0]
    assert s.allows("example.com")[0]
    assert not s.allows("legacy.example.com")[0]
    assert s.authorized and s.mode == "file"


def test_scope_txt_accepts_urls_comments_and_notes(tmp_path: Path):
    f = tmp_path / "scope.txt"
    f.write_text(
        "# in-scope subdomains\n"
        "api.example.com\n"
        "https://www.example.com/path\n"
        "- shop.example.com\n"
        "cdn.example.com   # edge host\n"
        "\n"
        "# Out of Scope\n"
        "legacy.example.com\n",
        encoding="utf-8",
    )
    s = Scope.load("", scope_file=str(f))
    assert s.allows("api.example.com")[0]
    assert s.allows("www.example.com")[0]
    assert s.allows("shop.example.com")[0]
    assert s.allows("cdn.example.com")[0]
    assert not s.allows("legacy.example.com")[0]
