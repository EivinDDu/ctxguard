# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-09-04

Initial release.

### Added
- `ctxguard scan <path>` — static scan of a repository for inbound
  prompt-injection payloads aimed at AI coding agents.
- Context classifier (`mcp-config`, `agent-instructions`, `agent-skill`,
  `docs`, `generic`) with per-context severity boosting.
- Detectors: regex rule table (instruction override, agent-directed
  imperatives, exfiltration, obfuscation), invisible-Unicode scanner with
  `U+E00xx` tag-run decoding, bidi / zero-width / PUA / homoglyph detection,
  layout smuggling, MCP `.mcp.json` structure walk, filename checks.
- Output formats: `text`, `json`, `sarif` (2.1.0), `markdown`.
- `--fail-on`, `--min-severity`, `--min-confidence`, `--all-text`,
  `--git-history`, `--exclude`, `-o/--output`.
- Suppression via `.ctxguardignore` and inline `ctxguard: ignore [RULE…]`
  comments.
- `ctxguard rules` — list all detection rules.
- CI matrix (Python 3.9–3.13, Linux + macOS) and SARIF self-scan.
