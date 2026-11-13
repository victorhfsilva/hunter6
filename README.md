# hunter6

Turn a folder of **custom scan-tool output** into one **FINDINGS file per
subdomain**, containing the vulnerabilities that are actually valid.

- Reads every file in a scan folder (JSON, JSONL, XML, CSV, plain text…).
- Extracts candidate vulnerabilities and attributes them to subdomains.
- Writes `FINDINGS/<subdomain>.md` (+ `.json`) for each subdomain found.
- Optionally **validates** candidates with an AI provider — the AI is free to
  test them live (scope-enforced) and only proven issues are marked validated.
- Uses **OpenCode skills** by default; override with `--skills DIR` or disable
  with `--no-skills`.
- Stdlib only. No runtime dependencies.

---

## Quick start

```bash
# 1. Inspect what the scans contain (offline, no network)
./bin/hunter6 parse ./scans

# 2. Triage offline: write FINDINGS/<subdomain>.md with candidates
./bin/hunter6 triage ./scans --no-ai

# 3. Triage with AI validation (sends requests to the scanned hosts)
export VERBOO_API_KEY=vbk_...          # or reuse ~/.config/opencode/opencode.json
./bin/hunter6 triage ./scans --authorized
```

Output:

```
hunter_out/scans/
├── FINDINGS.md                 # index of all subdomains
└── FINDINGS/
    ├── api.example.com.md      # one report per subdomain
    ├── api.example.com.json
    ├── www.example.com.md
    └── www.example.com.json
```

Or install the console script:

```bash
pipx install .
hunter6 triage ./scans --authorized
```

---

## How files are attributed to subdomains

Custom tools have no fixed schema, so attribution is layered (first wins):

1. **Host-like parent directory** — `scans/api.example.com/out.txt` → `api.example.com`.
2. **Host-like filename** — `nuclei_shop.example.com.json` → `shop.example.com`
   (tool prefixes separated by `_`/`-` are split off).
3. **Hosts inside the content** — from URLs or bare hostnames; the finding's
   own host is used when present.
4. Fallback bucket `_unknown` for candidates with no identifiable host.

Candidate extraction:

- **JSON / JSONL** — record objects with `url`/`host`/`matched-at`/`target`
  plus `type`/`template-id`/`name` and `severity`/`risk`/`level` fields;
  nested `info` blocks are merged. Containers (`results`, `findings`, `items`,
  `data`, …) are unwrapped. Duplicate records are deduped.
- **Plain text / CSV / XML** — lines containing a vulnerability keyword are
  classified by class (`RCE`, `SQL Injection`, `XSS`, `SSRF`, `IDOR`, …) and
  severity (`critical|high|medium|low|info`).
- Binary/oversized files are skipped and listed in the report.

---

## What the AI does

For each subdomain (bounded by `--max-hosts` / `--max-candidates`):

1. Receives the candidate list plus the skill index.
2. Loads the relevant skill(s) with `read_skill` (e.g. `hunt-idor`,
   `hunt-sqli`) and follows the playbook.
3. Reproduces each candidate with scope-enforced `probe` / `http_request`.
4. Calls `save_finding` **only** for reproduced issues, with evidence and the
   original scan file as `source`.
5. Anything not reproduced stays in the **Candidates (unvalidated)** section.

Each `FINDINGS/<subdomain>.md` therefore has two sections:
**Validated vulnerabilities** and **Candidates (unvalidated)**.

### Scope — controlling what the AI validates

By default the AI validates **every subdomain found in the scans**. You can
restrict (or narrow) that to specific subdomains in three ways:

```bash
# 1. A single subdomain (repeatable)
hunter6 triage ./scans --authorized --in-scope api.example.com
hunter6 triage ./scans --authorized --in-scope api.example.com --in-scope www.example.com

# 2. A txt file with one subdomain per line (URLs, ports, #comments OK)
hunter6 triage ./scans --authorized --scope-file in-scope.txt
hunter6 triage ./scans --authorized --scope in-scope.txt      # same flag

# 3. Combine: file hosts + extra --in-scope hosts
hunter6 triage ./scans --authorized --scope-file in-scope.txt --in-scope extra.example.com
```

`in-scope.txt` — one subdomain per line:

```text
api.example.com
www.example.com
https://shop.example.com/path
cdn.example.com   # edge
```

Subdomains **outside** the specified scope are still parsed and still get a
`FINDINGS/<subdomain>.md` (with candidates), but the AI does **not** send any
requests to them. Preview the effective scope without touching the network:

```bash
hunter6 scope ./scans --in-scope api.example.com
hunter6 scope ./scans --scope-file in-scope.txt
```

More controls:

| Flag | Effect |
|---|---|
| `--in-scope HOST` | add a subdomain to the validation allow-list (repeatable) |
| `--scope-file FILE` / `--scope FILE` | txt (one host/line) or scope.yaml |
| `--scope-mode strict` | exact host match only (no subdomains) |
| `--scope-mode off` | disable host restriction (loud warning) |
| `--exclude HOST` | out-of-scope host/pattern (repeatable) |

Out-of-scope always wins over in-scope. A denied request is skipped and
logged, never fatal. Network testing requires `--authorized` (or
`HUNTER6_AUTHORIZED=1`); offline runs (`--no-ai`) need no authorization.

---

## Skills

A skill is a directory with `SKILL.md` (YAML frontmatter: `name`,
`description`). hunter6 loads a compact index and the AI pulls full playbooks
on demand — it never dumps every skill into the prompt.

Load order (first match wins):

1. `--skills DIR` (repeatable)
2. `HUNTER6_SKILLS` (`:`-separated)
3. `./skills`
4. **`~/.config/opencode/skills`** — the OpenCode default
5. `~/.agents/skills`

```bash
./bin/hunter6 skills                       # list what was loaded
./bin/hunter6 skills --query idor --full
./bin/hunter6 triage ./scans --authorized --skills ./my-skills
./bin/hunter6 triage ./scans --authorized --no-skills
```

---

## AI providers

| Provider | Id | Wire format | Default model | Key env |
|---|---|---|---|---|
| **Verboo** | `verboo` | [OI] chat | `deepseek-v4.1-flash` | `VERBOO_API_KEY` |
| [OI] | `openai` | [OI] chat | `gpt-4o-mini` | `OPENAI_API_KEY` |
| OpenRouter | `openrouter` | [OI] chat | `openai/gpt-4o-mini` | `OPENROUTER_API_KEY` |
| Groq | `groq` | [OI] chat | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| Ollama | `ollama` | [OI] chat | `llama3.1` | (none) |
| Anthropic | `anthropic` | Messages API | `--model` | `ANTHROPIC_API_KEY` |
| Custom | `custom` | [OI] chat | `--model` | `CUSTOM_API_KEY` |

Resolution order (first wins): CLI flags → provider env → `HUNTER6_*` / `AI_*`
→ `~/.config/hunter6/config.json` → `~/.config/opencode/opencode.json` →
defaults. No key is stored in this repo.

---

## CLI

```
hunter6 triage <scan-dir> [options]   parse + (optionally) validate + write FINDINGS
hunter6 parse  <scan-dir> [--json]    offline: list hosts + candidates
hunter6 scope  <scan-dir> [options]   show effective validation scope
hunter6 skills [--query Q] [--full]   list loaded skills
hunter6 providers                     list providers/models/key state
```

Common `triage` options:

| Flag | Meaning |
|---|---|
| `--provider <id>` | AI provider (default `verboo`) |
| `--model <id>` | model override |
| `--base-url` / `--api-key` | endpoint overrides |
| `--skills <dir>` / `--no-skills` | skill library control |
| `--in-scope HOST` | restrict validation to this subdomain (repeatable) |
| `--scope-file FILE` / `--scope FILE` | txt of in-scope subdomains, or scope.yaml |
| `--scope-mode` / `--exclude` | strict/off modes, out-of-scope hosts |
| `--authorized` / `-y` | confirm authorization for live testing |
| `--out DIR` | output directory (default `hunter_out/<scan-dir>`) |
| `--max-hosts N` | max subdomains processed (default 25) |
| `--max-candidates N` | max candidates per subdomain (default 20) |
| `--max-steps N` | max AI turns per subdomain (default 12) |
| `--allow-shell` | enable `run_command` (not scope-checked) |
| `--dry-run` | no network requests |
| `--no-ai` | offline: candidates only |
| `-q` / `--quiet` | less output |

---

## Tools available to the AI

| Tool | Scope-checked | Purpose |
|---|---|---|
| `list_skills` / `search_skills` / `read_skill` | n/a | find and load playbooks |
| `probe` | yes | quick status/title/server |
| `http_request` | yes | crafted requests (method, headers, body) |
| `dns_lookup` | yes | resolve an in-scope host |
| `save_finding` | n/a | persist a validated finding |
| `list_findings` | n/a | list saved findings |
| `run_command` | **no** | local shell; opt-in via `--allow-shell` |
| `finish` | n/a | stop and summarize |

---

## Safety

- Only the scanned hosts are in scope; denials are logged in the run output.
- `run_command` is off by default because a shell cannot be scope-enforced.
- The AI is told to save only reproduced issues; unreproduced candidates are
  clearly separated, never presented as validated.
- Use only against targets you are authorized to test.

---

## Development

```bash
PYTHONPATH=. python3 -m pytest tests -q
```

Coverage: scan parsing (JSON/JSONL/array/plaintext, path attribution, dedupe,
binary skip), per-subdomain report writing, index generation, validated
dedupe, per-host AI-scope filtering, plus scope/providers/skill tests.

## License

MIT. For authorized security testing only.
