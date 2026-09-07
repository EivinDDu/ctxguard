# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-09-06

### Added
- **Benchmark harness** — `ctxguard bench` scores the detectors against a
  labelled corpus in `benchmark/` (38 cases) and reports precision, recall, F1,
  false-positive rate and per-rule accuracy. `--min-recall` / `--max-fp-rate` /
  `--min-rule-accuracy` make it a CI gate; CI now fails on any detection
  regression or new false positive.
- **`CG406` — deobfuscated rescan.** Zero-width / Unicode-Tag characters are
  stripped and common Cyrillic/Greek homoglyphs folded to ASCII, then the rule
  table is re-run. Catches `I​g​n​o​r​e all previous instructions` and
  `іgnоrе …`-style evasions that defeat a raw regex.
- **`CG107`** — attempts to make the model disclose its own prompt / prior
  context (`repeat the text above verbatim`, `what is your system prompt`).
- **`CG203`** — fake context boundaries and `system override` banners used to
  inject a task into retrieved / tool-result content.
- **`CG307`** — DNS-based exfiltration (`dig $(cat …).attacker`).
- **`CG308`** — exfiltration / persistence via `git remote add` + `git push` to
  a non-GitHub URL, or a `postinstall` hook that shells out.

### Changed
- `CG302` callback-URL list extended with tunnel / relay services
  (`trycloudflare.com`, `loca.lt`, `localtunnel.me`, `serveo.net`, `lhr.life`,
  `smee.io`, `hookb.in`, `webhookrelay.com`, `dnslog.cn`, `ngrok-free.app`).
- `CG103` no longer fires on ordinary `### System Requirements`-style headings
  (needs a bare role header, a trailing colon, or `### System prompt`).
- `CG802` (instruction-like filename) now needs a real imperative phrase, not
  just a keyword like `curl` — `curl_download.md` is no longer flagged.

### Fixed
- Two false positives found by the new benchmark corpus (the `CG103` and
  `CG802` cases above).

## [0.2.0] - 2026-09-07

### Added
- `--changed [REF]` — scan only files changed vs `REF` (default `HEAD`) plus
  staged / unstaged / untracked files. Fast pre-commit and PR-diff gating.
- Encoded-payload detector: base64 and hex blobs are decoded and the plaintext
  rescanned (`CG404`, with the decoded text in the finding). `CG403` is now the
  low-severity "long blob that doesn't decode to text" note.
- `CG106` — jailbreak / guardrail-removal phrasing (`developer mode`,
  `do anything now`, `ignore your guidelines`, …).
- `CG306` — reverse-shell command patterns (`bash -i >& /dev/tcp/…`, `nc -e`,
  `python -c '…socket…'`).

### Changed
- `ctxguard rules` now lists the analytic detectors (`CG4xx`–`CG8xx`) alongside
  the regex rules.
- `CG403` moved from the regex table into the encoded-payload detector.

## [0.1.0] - 2026-09-05

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
- CI matrix (Python 3.9–3.13, Linux + macOS); dogfood self-scan and SARIF
  artifact build on every run.
- `.pre-commit-hooks.yaml` — usable as a hosted pre-commit repo
  (`repo: https://github.com/EivinDDu/ctxguard`, `rev: v0.1.0`).
- `action.yml` — composite GitHub Action (`uses: EivinDDu/ctxguard@v0.1.0`)
  with `path`, `fail-on`, `args`, and `version` inputs.
