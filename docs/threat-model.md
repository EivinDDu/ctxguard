# ctxguard threat model

## What we are defending

A developer clones or opens a repository they do not fully trust and points an
AI coding agent (Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Aider,
Gemini CLI…) at it. The agent has tools: it can read files, run shell commands,
edit code, open URLs, and call MCP servers.

## The attacker

Anyone who can influence text that lands in the repository:

- the repo owner (malicious open-source project, typosquatted package repo)
- a contributor who opens a pull request
- an issue or discussion author (agents that triage issues read this text)
- an upstream dependency whose README / MCP manifest is vendored in

The attacker cannot execute code directly, but they can place **text** that the
agent will read as part of its context.

## Attacker goals

| Goal | Mechanism |
|---|---|
| Remote code execution | get the agent to run `curl … \| sh`, a poisoned build step, or a malicious MCP server command |
| Secret exfiltration | get the agent to read `.env` / `~/.aws/credentials` / SSH keys and send them to an attacker endpoint |
| Silent persistence | get the agent to write a backdoor or modify CI, and *not tell the user* |
| Supply-chain pivot | get the agent to add a malicious dependency or commit to another repo |

## Delivery surfaces ctxguard inspects

1. **Agent instruction files** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
   `.github/copilot-instructions.md`, `.clinerules`, … loaded verbatim as
   standing instructions. Highest severity multiplier.
2. **MCP configuration** — `.mcp.json` / `mcp.json`. Tool `description` fields
   are injected into the model context and are a known poisoning vector
   (CVE-2025-54136). Launch `command` / `args` can themselves be malicious.
3. **Agent skills** — `SKILL.md` and skill bundles.
4. **Docs** — `README`, `CONTRIBUTING`, `docs/**`, and any `*.md` / `*.rst` /
   `*.txt`. The agent reads these to "understand the project".
5. **Filenames** — some agents concatenate paths into prompts; invisible or
   instruction-shaped filenames are an injection channel.
6. **Git history** (opt-in, `--git-history`) — commit messages, which stand in
   for PR/issue bodies fed to triage agents.

## Techniques ctxguard looks for

- **Direct override** — "ignore previous instructions", persona resets, chat
  role/template delimiters smuggled into prose.
- **Concealed instructions** — HTML comments, `display:none` / zero-font spans,
  whitespace that pushes text off-screen, long base64 blobs.
- **Invisible Unicode** — Unicode Tag characters (`U+E00xx`, decoded and shown
  in the finding), bidi overrides (Trojan Source), zero-width runs, Private Use
  Area smuggling, homoglyph words.
- **Exfiltration primitives** — instructions to send secrets out, callback / OOB
  URLs, auto-rendering markdown images with query strings, pipe-to-shell.
- **"Don't tell the user"** — instructions to suppress disclosure.

## Explicit non-goals

- **Not a secret scanner.** Use `trufflehog` / `gitleaks` for that.
- **Not a runtime MCP monitor.** Use `mcp-scan` for live tool-call inspection.
- **Not SAST.** ctxguard does not look at program logic.
- **No semantic understanding.** A novel injection with no lexical markers, or
  one written in a language ctxguard's rules don't cover, can pass. ctxguard
  raises the cost of an attack and puts suspicious content in front of a human;
  it is not a guarantee.

## False positives

Security documentation *about* prompt injection (including this repository) will
match. Suppress with `.ctxguardignore` entries or inline
`<!-- ctxguard: ignore CG101 -->` markers, and raise `--min-confidence` in CI.
