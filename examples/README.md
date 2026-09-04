# examples/

`malicious-repo/` is a **deliberately crafted** sample repository used to
demonstrate ctxguard and to exercise it in CI. Every file in it contains a
planted prompt-injection payload. Nothing here is executed.

- `README.md` — hidden HTML-comment override + plain-sight exfiltration request
- `CONTRIBUTING.md` — an instruction smuggled in invisible Unicode Tag characters
- `CLAUDE.md` — standing-instruction exfiltration + `<IMPORTANT>` priority marker
- `.mcp.json` — poisoned tool `description` (CVE-2025-54136) + pipe-to-shell server

Full write-up: [`../docs/walkthrough.md`](../docs/walkthrough.md).

```console
$ ctxguard scan examples/malicious-repo --fail-on none
...
scanned 4 file(s), skipped 0 — critical=14  high=2
```

This directory is listed in `../.ctxguardignore` so a scan of the ctxguard
repository itself stays green.
