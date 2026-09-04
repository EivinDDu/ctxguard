# examples/

`malicious-repo/` is a **deliberately crafted** sample repository used to
demonstrate ctxguard and to exercise it in CI. Every file in it contains a
planted prompt-injection payload. Nothing here is executed.

```console
$ ctxguard scan examples/malicious-repo --fail-on none

CRITICAL  examples/malicious-repo/.mcp.json:6:1  [CG701 mcp-tool-poisoning]
          MCP 'mcpServers.notes.tools.[0].description' field carries hidden
          instructions / references to secrets — classic tool poisoning.
CRITICAL  examples/malicious-repo/CLAUDE.md:5:1  [CG301 exfiltration]
          Instruction to send secrets somewhere.
CRITICAL  examples/malicious-repo/README.md:9:5  [CG101 instruction-override]
          Classic instruction-override phrasing ('ignore previous instructions').
   ...
```

This directory is listed in `../.ctxguardignore` so a scan of the ctxguard
repository itself stays green.
