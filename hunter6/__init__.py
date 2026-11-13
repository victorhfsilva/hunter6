"""hunter6 — triage a folder of scan results into per-subdomain FINDINGS.

Reads custom scan-tool output, groups candidate vulnerabilities by subdomain,
optionally validates them with an AI provider (skills-guided, scope-enforced),
and writes one FINDINGS file per subdomain.
"""
from __future__ import annotations

__version__ = "0.1.0"
