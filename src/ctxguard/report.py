"""Render a :class:`~ctxguard.scanner.ScanResult` in the requested format."""

from __future__ import annotations

import json
from typing import List

from ctxguard import __version__
from ctxguard.finding import Finding, Severity
from ctxguard.scanner import ScanResult

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def render(result: ScanResult, fmt: str, *, color: bool = True) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return _json(result)
    if fmt == "sarif":
        return _sarif(result)
    if fmt == "markdown":
        return _markdown(result)
    if fmt == "text":
        return _text(result, color=color)
    raise ValueError(f"unknown format {fmt!r}")


# ---------------------------------------------------------------------------


def _c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def _text(result: ScanResult, *, color: bool) -> str:
    out: List[str] = []
    if not result.findings:
        out.append(_c("✓ ctxguard: no prompt-injection indicators found", "\033[1;32m", color))
    else:
        for f in result.findings:
            head = _c(f.severity.label.upper().rjust(8), _COLORS[f.severity], color)
            loc = _c(f"{f.path}:{f.line}:{f.column}", _BOLD, color)
            out.append(f"{head}  {loc}  [{f.rule_id} {f.category}]")
            out.append(f"          {f.message}")
            if f.snippet:
                out.append(_c(f"          │ {f.snippet}", _DIM, color))
            meta = f"context={f.context} confidence={f.confidence}"
            if f.reference:
                meta += f"  {f.reference}"
            out.append(_c(f"          {meta}", _DIM, color))
            out.append("")

    counts = result.counts_by_severity()
    summary = "  ".join(
        f"{k}={v}" for k, v in counts.items() if v or k in ("critical", "high", "medium")
    )
    out.append(
        f"{_c('scanned', _BOLD, color)} {result.files_scanned} file(s), "
        f"skipped {result.files_skipped} — {summary}"
    )
    for err in result.errors:
        out.append(_c(f"! {err}", "\033[33m", color))
    return "\n".join(out)


def _json(result: ScanResult) -> str:
    payload = {
        "tool": "ctxguard",
        "version": __version__,
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "counts": result.counts_by_severity(),
            "max_severity": (result.max_severity().label if result.max_severity() else None),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _markdown(result: ScanResult) -> str:
    lines = [f"# ctxguard report", ""]
    counts = result.counts_by_severity()
    lines.append(
        f"**{len(result.findings)} finding(s)** across {result.files_scanned} file(s) "
        f"— critical: {counts['critical']}, high: {counts['high']}, "
        f"medium: {counts['medium']}, low: {counts['low']}, info: {counts['info']}"
    )
    lines.append("")
    if not result.findings:
        lines.append("_No prompt-injection indicators found._")
        return "\n".join(lines)
    lines += ["| Severity | Location | Rule | Message |", "|---|---|---|---|"]
    for f in result.findings:
        msg = f.message.replace("|", "\\|")
        lines.append(
            f"| {f.severity.label} | `{f.path}:{f.line}` | {f.rule_id} | {msg} |"
        )
    return "\n".join(lines)


def _sarif(result: ScanResult) -> str:
    rule_index: dict = {}
    rules: list = []
    sarif_results: list = []
    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    for f in result.findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rule = {
                "id": f.rule_id,
                "name": f.category,
                "shortDescription": {"text": f.message},
                "properties": {"category": f.category},
            }
            if f.reference:
                rule["helpUri"] = f.reference
            rules.append(rule)
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": level_map[f.severity],
                "message": {"text": f"{f.message} (confidence: {f.confidence})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column)},
                        }
                    }
                ],
                "properties": {"severity": f.severity.label, "context": f.context},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ctxguard",
                        "version": __version__,
                        "informationUri": "https://github.com/EivinDDu/ctxguard",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
