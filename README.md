# ctxguard

**Scan a repository for prompt-injection payloads *before* you point an AI coding agent at it.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## The gap this fills

Every current MCP / AI-agent security scanner points *outward* — it probes a
remote MCP server, or audits the agent framework you are building. Almost nothing
points *inward* at the **untrusted repository you are about to open in Cursor,
Claude Code, Copilot, or Windsurf**.

That repo is attacker-influenced text. The moment your agent reads its
`README.md`, `CLAUDE.md`, `.cursorrules`, `.mcp.json`, issue templates, or even a
filename, any instructions hidden in that content enter the model's context.
Cloud Security Alliance research in 2026 documented "README instruction
injection" against coding agents with attack success rates of 41–84%, and MCP
tool-description poisoning (CVE-2025-54136) works the same way.

`ctxguard` is a fast, dependency-free static scanner that flags that content so a
human reviews it first.

## What it detects

| Family | Examples |
|---|---|
| **Instruction override** | `ignore all previous instructions`, `you are now…`, chat-template tokens (`<system>`, `[INST]`, `<\|im_start\|>`), `do not tell the user`, `<IMPORTANT>` priority markers |
| **Agent-directed imperatives** | sentences addressed to "the AI / assistant / agent" that also name an action (`run`, `curl`, `exfiltrate`, `install`, `push`) |
| **Data exfiltration** | instructions to send `.env` / tokens / file contents somewhere, callback URLs (`webhook.site`, `ngrok`, `oast`, `requestbin`…), markdown images with query strings, `curl … \| sh` |
| **Hidden Unicode** | Unicode **Tag** characters `U+E00xx` (decoded and shown), bidirectional overrides (Trojan Source), zero-width runs, Private-Use-Area smuggling, Latin/Cyrillic/Greek homoglyph words |
| **Layout smuggling** | instruction text pushed off-screen by whitespace, `display:none` / `color:#fff` / `font-size:0` spans, instruction-bearing HTML comments, long base64 blobs |
| **MCP config poisoning** | `.mcp.json` `description` / `instructions` fields carrying hidden directives or secret references; server launch commands that pipe a download into a shell |
| **Filename injection** | control / invisible / bidi characters in filenames, filenames that read like an instruction |

Severity is **boosted by context**: the same string is `medium` in a source
comment but `critical` in `.mcp.json` or `CLAUDE.md`, because agents load those
files as authoritative instructions.

## Install

```bash
pipx install ctxguard        # recommended
# or
pip install ctxguard
```

From source:

```bash
git clone https://github.com/EivinDDu/ctxguard
cd ctxguard
pip install -e ".[dev]"
```

## Usage

```bash
# scan the current repo
ctxguard scan .

# scan a repo you just cloned, before opening it in your editor
ctxguard scan ../suspicious-repo

# machine-readable output
ctxguard scan . --format json  -o ctxguard.json
ctxguard scan . --format sarif -o ctxguard.sarif   # upload to GitHub code scanning

# gate a pipeline
ctxguard scan . --fail-on medium --git-history

# tune the noise
ctxguard scan . --min-severity medium --min-confidence medium

# list every rule
ctxguard rules
```

By default `ctxguard` only reads files an agent treats as context (docs, rule
files, MCP config, `*.md`, `*.txt`, config formats). Add `--all-text` to sweep
source files too.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | completed; nothing at or above `--fail-on` |
| `1` | findings at or above `--fail-on` (default: `high`) |
| `2` | usage / runtime error |

### Pre-commit hook

```yaml
- repo: local
  hooks:
    - id: ctxguard
      name: ctxguard
      entry: ctxguard scan . --fail-on high
      language: system
      pass_filenames: false
```

## How it works

```
path ─▶ file walk (skips vendored dirs, binaries, >1 MB)
     ─▶ decode (utf-8 / utf-16 / latin-1), keep invisible chars intact
     ─▶ classify context (mcp-config │ agent-instructions │ agent-skill │ docs │ generic)
     ─▶ run detectors:
          • regex rule table          (ctxguard/rules.py)
          • invisible-Unicode scanner  (decodes U+E00xx tag runs)
          • layout / smuggling scanner
          • MCP JSON structure walk
          • filename scanner
     ─▶ context-adjust severity ─▶ sort ─▶ render (text │ json │ sarif │ markdown)
```

No network calls. No LLM. Deterministic.

## Limitations

- Static pattern matching: a novel paraphrase with no known markers can slip
  through, and benign security documentation *about* prompt injection will
  produce findings (tune with `--min-confidence`).
- Not a replacement for [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan)
  (runtime MCP), secret scanners, or SAST — it covers the one thing they don't.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
