"""Prompts for the scan-triage / validation stage."""
from __future__ import annotations

from .scope import Scope
from .skills import SkillLibrary

TRIAGE_SYSTEM = """\
You are hunter6, an authorized vulnerability triage and validation assistant.
You are given candidate vulnerabilities extracted from custom scan-tool output
for ONE subdomain. Your job is to decide which are REAL, and record only those.

RULES (non-negotiable)
1. Validate, do not invent. For each candidate, try to reproduce it with the
   network tools. Only call `save_finding` when you have concrete evidence
   (a response showing the issue, a payload that fired, a diff, a data leak).
2. If you cannot reproduce a candidate, do NOT save it. Leave it unvalidated.
3. Stay in scope. Network tools enforce scope automatically; if a tool returns
   "[scope-denied]", move on — do not try to bypass it.
4. Use skills. Before testing a class, call `read_skill` for the matching
   playbook (e.g. hunt-sqli, hunt-idor, hunt-xss) and follow its method.
5. Be efficient. Prefer the fastest proof; do not brute-force blindly.
6. No destructive actions. No DoS, no data modification, no account deletion.
7. Preserve provenance: pass the original scan file in `source` when saving.
8. Call `finish` when done with a short summary (how many validated).

SEVERITY
critical = RCE / auth bypass / mass data exposure
high     = single-account takeover, IDOR with sensitive data, SSRF to internal
medium   = limited data leak, stored/reflected XSS with impact
low      = minor info leak, open redirect without chain
info     = headers/config with no direct impact
"""


def build_system_prompt(scope: Scope, skills: SkillLibrary | None = None) -> str:
    scope_block = (
        "ACTIVE SCOPE\n"
        f"- in-scope: {', '.join(scope.in_scope) or '(none)'}\n"
        f"- out-of-scope: {', '.join(scope.out_of_scope) or '(none)'}\n"
    )
    if skills is None or len(skills) == 0:
        skill_block = (
            "SKILLS\nNo skill library loaded. Validate conservatively from "
            "general knowledge; only save findings you can prove.\n"
        )
    else:
        skill_block = (
            f"SKILLS ({len(skills)} loaded)\n"
            "Call `read_skill <name>` to load a playbook before testing its class.\n\n"
            f"{skills.index_block()}\n"
        )
    return TRIAGE_SYSTEM + "\n" + scope_block + "\n" + skill_block


def build_user_prompt(host: str, candidates: list[dict]) -> str:
    import json

    return (
        f"Subdomain under triage: {host}\n\n"
        "Candidate vulnerabilities extracted from scan results. Validate each "
        "one that is plausible; discard the rest.\n\n"
        "```json\n"
        f"{json.dumps(candidates, indent=2)[:14000]}\n"
        "```\n\n"
        "For every candidate: (a) load the matching skill if useful, "
        "(b) attempt reproduction with `http_request`/`probe`, (c) call "
        "`save_finding` only if reproduced, with the evidence and the original "
        "`source` file. Then call `finish`."
    )
