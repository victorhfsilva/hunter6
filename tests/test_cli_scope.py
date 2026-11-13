"""CLI scope-flag tests: --in-scope / --scope-file / --scope-mode / --exclude."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6.cli import _build_scope  # noqa: E402
from hunter6.scope import Scope  # noqa: E402


def _ns(**kw):
    base = dict(scope_file=None, in_scope=[], exclude=[], scope_mode=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_in_scope_flag_single_host():
    scope = _build_scope(_ns(in_scope=["api.example.com"]), Path("."))
    assert scope is not None
    assert scope.allows("api.example.com")[0]
    assert not scope.allows("other.example.com")[0]
    assert scope.source == "--in-scope"


def test_in_scope_flag_multiple_hosts():
    scope = _build_scope(
        _ns(in_scope=["api.example.com", "www.example.com"]), Path(".")
    )
    assert scope.allows("api.example.com")[0]
    assert scope.allows("www.example.com")[0]
    assert not scope.allows("shop.example.com")[0]


def test_scope_file_txt_list(tmp_path: Path):
    f = tmp_path / "scope.txt"
    _write(f, "api.example.com\nwww.example.com\n")
    scope = _build_scope(_ns(scope_file=str(f)), tmp_path)
    assert scope.allows("api.example.com")[0]
    assert scope.allows("www.example.com")[0]
    assert not scope.allows("cdn.example.com")[0]
    assert scope.source == str(f)


def test_scope_file_and_in_scope_merge(tmp_path: Path):
    f = tmp_path / "scope.txt"
    _write(f, "api.example.com\n")
    scope = _build_scope(
        _ns(scope_file=str(f), in_scope=["www.example.com"]), tmp_path
    )
    assert scope.allows("api.example.com")[0]
    assert scope.allows("www.example.com")[0]


def test_exclude_wins(tmp_path: Path):
    f = tmp_path / "scope.txt"
    _write(f, "api.example.com\nadmin.example.com\n")
    scope = _build_scope(_ns(scope_file=str(f), exclude=["admin.example.com"]), tmp_path)
    assert scope.allows("api.example.com")[0]
    assert not scope.allows("admin.example.com")[0]


def test_strict_disables_subdomains(tmp_path: Path):
    f = tmp_path / "scope.txt"
    _write(f, "example.com\n")
    scope = _build_scope(_ns(scope_file=str(f), scope_mode="strict"), tmp_path)
    assert scope.allows("example.com")[0]
    assert not scope.allows("api.example.com")[0]


def test_no_flags_returns_none_for_derivation():
    assert _build_scope(_ns(), Path(".")) is None


def test_scope_mode_strict_derives_from_scans(tmp_path: Path):
    scans = tmp_path / "scans"
    _write(scans / "api.example.com" / "r.txt", "api.example.com XSS (medium)\n")
    scope = _build_scope(_ns(scope_mode="strict"), scans)
    assert scope is not None
    assert scope.allows("api.example.com")[0]
    assert not scope.allows("x.api.example.com")[0]
