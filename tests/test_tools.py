"""Toolbox tests — scope enforcement, dry-run, findings persistence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter6.scope import Scope  # noqa: E402
from hunter6.tools import FindingsStore, ToolBox  # noqa: E402


def _box(tmp_path, *, scope=None, **kw):
    scope = scope or Scope.from_target("example.com")
    return ToolBox(scope=scope, findings=FindingsStore(tmp_path), **kw)


def test_http_request_denied_is_skipped(tmp_path):
    box = _box(tmp_path)
    out = box.http_request("GET", "https://evil.test/")
    assert out.startswith("[scope-denied]")
    assert box.denied and not box.requests


def test_http_request_allowed_dry_run(tmp_path):
    box = _box(tmp_path, dry_run=True)
    out = box.http_request("GET", "https://example.com/")
    assert out.startswith("[dry-run]")
    assert box.requests and not box.denied


def test_probe_denied(tmp_path):
    box = _box(tmp_path)
    assert box.probe("https://other.test").startswith("[scope-denied]")


def test_dns_denied(tmp_path):
    box = _box(tmp_path)
    assert box.dns_lookup("other.test").startswith("[scope-denied]")


def test_dns_dry_run(tmp_path):
    box = _box(tmp_path, dry_run=True)
    assert "would resolve" in box.dns_lookup("example.com")


def test_save_finding_persists(tmp_path):
    box = _box(tmp_path)
    msg = box.save_finding(
        title="IDOR in /orders",
        severity="high",
        vuln_class="idor",
        url="https://example.com/orders/2",
        evidence="GET /orders/2 returned user 2's email",
    )
    assert msg.startswith("[saved]")
    data = json.loads((tmp_path / "FINDINGS.json").read_text())
    assert data[0]["title"] == "IDOR in /orders"
    assert data[0]["severity"] == "high"
    assert data[0]["status"] == "validated"
    md = (tmp_path / "FINDINGS.md").read_text()
    assert "IDOR in /orders" in md
    assert "Validated vulnerabilities" in md


def test_shell_disabled_by_default(tmp_path):
    box = _box(tmp_path)
    assert box.run_command("echo hi").startswith("[disabled]")


def test_shell_deny_list(tmp_path):
    box = _box(tmp_path, allow_shell=True)
    assert box.run_command("rm -rf /").startswith("[blocked]")


def test_shell_dry_run(tmp_path):
    box = _box(tmp_path, allow_shell=True, dry_run=True)
    assert box.run_command("echo hi").startswith("[dry-run]")


def test_finish_sets_state(tmp_path):
    box = _box(tmp_path)
    box.finish("done")
    assert box.finished and box.summary == "done"


def test_dispatch_unknown(tmp_path):
    box = _box(tmp_path)
    assert box.dispatch("nope", {}) == "[error] unknown tool: nope"


def test_schemas_have_required_fields(tmp_path):
    box = _box(tmp_path)
    for schema in box.schemas():
        assert {"name", "description", "parameters"} <= set(schema)
