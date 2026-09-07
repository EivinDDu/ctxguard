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

**→ See [`docs/walkthrough.md`](docs/walkthrough.md) for a worked example: five
planted attacks in a sample repo, and the scan that catches every one.**

## What it detects

| Family | Examples |
|---|---|
| **Instruction override** | `ignore all previous instructions`, `you are now…`, chat-template tokens (`<system>`, `[INST]`, `<\|im_start\|>`), `do not tell the user`, `<IMPORTANT>` priority markers, jailbreak / guardrail-removal phrasing (`developer mode`, `do anything now`, `ignore your guidelines`) |
| **Agent-directed imperatives** | sentences addressed to "the AI / assistant / agent" that also name an action (`run`, `curl`, `exfiltrate`, `install`, `push`) |
| **Data exfiltration & RCE** | instructions to send `.env` / tokens / file contents somewhere, callback URLs (`webhook.site`, `ngrok`, `oast`, `requestbin`…), markdown images with query strings, `curl … \| sh`, reverse-shell one-liners (`bash -i >& /dev/tcp/…`) |
| **Data exfiltration & RCE** *(cont.)* | DNS exfiltration (`dig $(cat …).attacker`), `git remote add` + `git push` to a non-GitHub URL, `postinstall` hooks that shell out |
| **Context / prompt disclosure** | `repeat the text above verbatim`, `what is your system prompt`, fake `--- END OF DOCUMENT ---` / `system override:` boundaries injected into retrieved content |
| **Hidden Unicode** | Unicode **Tag** characters `U+E00xx` (decoded and shown), bidirectional overrides (Trojan Source), zero-width runs, Private-Use-Area smuggling, Latin/Cyrillic/Greek homoglyph words |
| **Deobfuscated rescan** | strips zero-width / tag characters and folds homoglyphs, then re-runs every rule — catches `I​g​n​o​r​e all previous instructions` and `іgnоrе …` evasions |
| **Encoded payloads** | base64 / hex blobs are decoded and the plaintext rescanned — a hidden `ignore all previous instructions…` inside a base64 string is surfaced with the decoded text |
| **Layout smuggling** | instruction text pushed off-screen by whitespace, `display:none` / `color:#fff` / `font-size:0` spans, instruction-bearing HTML comments |
| **MCP config poisoning** | `.mcp.json` `description` / `instructions` fields carrying hidden directives or secret references; server launch commands that pipe a download into a shell |
| **Filename injection** | control / invisible / bidi characters in filenames, filenames that spell out an imperative |

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

# scan only what changed — fast pre-commit / PR gating
ctxguard scan . --changed              # vs HEAD (+ staged/unstaged/untracked)
ctxguard scan . --changed origin/main  # vs a base branch

# machine-readable output
ctxguard scan . --format json  -o ctxguard.json
ctxguard scan . --format sarif -o ctxguard.sarif   # upload to GitHub code scanning

# gate a pipeline
ctxguard scan . --fail-on medium --git-history

# tune the noise
ctxguard scan . --min-severity medium --min-confidence medium

# list every rule
ctxguard rules

# score the detectors against the labelled corpus
ctxguard bench
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
# .pre-commit-config.yaml
- repo: https://github.com/EivinDDu/ctxguard
  rev: v0.3.0
  hooks:
    - id: ctxguard             # add: args: ["--changed"] for staged-only scans
```

### GitHub Action

```yaml
# .github/workflows/ctxguard.yml
name: ctxguard
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EivinDDu/ctxguard@v0.3.0
        with:
          fail-on: high        # optional (default: high)
          # path: .
          # args: --changed origin/main   # PR-diff-only scan
```

### Suppressing findings

Known-good matches (your own security docs, test fixtures) can be silenced two
ways:

- **`.ctxguardignore`** at the scan root — one glob per line, optionally
  scoped to specific rule ids:

  ```
  docs/threat-model.md            # ignore every rule for this file
  examples/**                     # ignore a whole tree
  SECURITY.md:CG101,CG401         # ignore only these rules here
  ```

- **Inline comment** on the flagged line or the line above it:

  ```markdown
  <!-- ctxguard: ignore CG401 -- example payload documented on purpose -->
  ```

## How it works

```
path ─▶ file walk (skips vendored dirs, binaries, >1 MB)
     ─▶ decode (utf-8 / utf-16 / latin-1), keep invisible chars intact
     ─▶ classify context (mcp-config │ agent-instructions │ agent-skill │ docs │ generic)
     ─▶ run detectors:
          • regex rule table           (ctxguard/rules.py)
          • invisible-Unicode scanner   (decodes U+E00xx tag runs)
          • deobfuscated rescan         (strip zero-width, fold homoglyphs, re-run rules)
          • encoded-payload scanner     (decodes base64 / hex, rescans plaintext)
          • layout / smuggling scanner
          • MCP JSON structure walk
          • filename scanner
     ─▶ context-adjust severity ─▶ sort ─▶ render (text │ json │ sarif │ markdown)
```

No network calls. No LLM. Deterministic.

## Benchmark

`ctxguard bench` runs the detectors over a labelled corpus in [`benchmark/`](benchmark)
(20 malicious fixtures across every family, 18 realistic benign ones) and reports
precision / recall / F1 / false-positive rate. CI fails the build on any
regression:

```
cases: 38   TP 20  FN 0  FP 0  TN 18
precision 1.000   recall 1.000   F1 1.000   FP-rate 0.000   rule-accuracy 1.000
```

The benign fixtures are the point — normal `README`s, a `SECURITY.md`, setup
docs that mention API keys, `### System Requirements` headings — content that
*looks* adjacent to an attack but must not trip the scanner.

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
ctxguard bench          # detection score against benchmark/
```

Adding a detector? Add a fixture to `benchmark/malicious/` (and a benign
counterpart if it could misfire), list it in `benchmark/cases.jsonl`, and keep
`ctxguard bench` at 100% recall / 0 false positives.

## License

MIT
