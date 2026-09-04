"""Detectors turn a :class:`~ctxguard.document.Document` into findings.

Two kinds live here:

* ``run_rules`` applies the regex table in :mod:`ctxguard.rules`.
* Hand-written detectors catch things a single regex cannot: invisible Unicode
  (with decoding of smuggled ASCII), bidi control abuse, oversized/padded lines,
  MCP config structure walks, and filename tricks.

Every detector yields :class:`~ctxguard.finding.Finding` objects with a
context-adjusted severity via :func:`adjust_severity`.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Iterable, List

from ctxguard.contexts import (
    CONTEXT_SEVERITY_BOOST,
    CTX_MCP_CONFIG,
)
from ctxguard.document import Document
from ctxguard.finding import Finding, Severity
from ctxguard.rules import RULES

Detector = Callable[[Document], Iterable[Finding]]
_DETECTORS: List[Detector] = []


def detector(func: Detector) -> Detector:
    _DETECTORS.append(func)
    return func


def all_detectors() -> List[Detector]:
    return list(_DETECTORS)


def adjust_severity(base: Severity, context: str) -> Severity:
    boost = CONTEXT_SEVERITY_BOOST.get(context, 0)
    return Severity(min(int(Severity.CRITICAL), int(base) + boost))


# ---------------------------------------------------------------------------
# Regex rule runner
# ---------------------------------------------------------------------------


@detector
def run_rules(doc: Document) -> Iterable[Finding]:
    for rule in RULES:
        for match in rule.pattern.finditer(doc.raw_text):
            line, col = doc.locate(match.start())
            yield Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=adjust_severity(rule.base_severity, doc.context),
                message=rule.message,
                path=doc.path,
                line=line,
                column=col,
                snippet=doc.snippet_for_line(line),
                confidence=rule.confidence,
                reference=rule.reference,
                context=doc.context,
                extra={"matched": _clip(match.group(0))},
            )


def _clip(text: str, limit: int = 160) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit] + "…"


# ---------------------------------------------------------------------------
# Invisible / confusable Unicode
# ---------------------------------------------------------------------------

# Zero-width and joiner characters that carry no glyph.
_ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
}

# Bidirectional formatting characters (Trojan Source style reordering).
_BIDI = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}


def _is_tag_char(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _decode_tag_run(run: str) -> str:
    out = []
    for ch in run:
        cp = ord(ch)
        if cp == 0xE0001:  # LANGUAGE TAG
            continue
        out.append(chr(cp - 0xE0000))
    return "".join(out)


@detector
def invisible_unicode(doc: Document) -> Iterable[Finding]:
    for lineno, line in enumerate(doc.lines, start=1):
        # --- Unicode Tag characters: often smuggle a full ASCII instruction ---
        tag_positions = [i for i, ch in enumerate(line) if _is_tag_char(ch)]
        if tag_positions:
            run = "".join(ch for ch in line if _is_tag_char(ch))
            decoded = _decode_tag_run(run)
            printable = "".join(c for c in decoded if c.isprintable())
            yield Finding(
                rule_id="CG501",
                category="hidden-unicode",
                severity=adjust_severity(Severity.HIGH, doc.context),
                message=(
                    "Unicode Tag characters (U+E00xx) — invisible text that many "
                    "models still read. Decoded: "
                    + (repr(printable) if printable else "<non-printable>")
                ),
                path=doc.path,
                line=lineno,
                column=tag_positions[0] + 1,
                snippet=doc.snippet_for_line(lineno),
                confidence="high",
                reference="https://trojansource.codes/",
                context=doc.context,
                extra={"decoded": printable, "count": len(tag_positions)},
            )

        # --- Bidi controls ---
        for idx, ch in enumerate(line):
            if ch in _BIDI:
                yield Finding(
                    rule_id="CG502",
                    category="hidden-unicode",
                    severity=adjust_severity(Severity.HIGH, doc.context),
                    message=f"Bidirectional control character ({_BIDI[ch]}); "
                    "can reorder text so the rendered form differs from the bytes.",
                    path=doc.path,
                    line=lineno,
                    column=idx + 1,
                    snippet=doc.snippet_for_line(lineno),
                    confidence="high",
                    reference="https://trojansource.codes/",
                    context=doc.context,
                )

        # --- Zero-width runs ---
        zw = [(i, ch) for i, ch in enumerate(line) if ch in _ZERO_WIDTH]
        if zw:
            # A BOM alone at the very start of the file is benign noise.
            if not (lineno == 1 and len(zw) == 1 and zw[0][0] == 0 and zw[0][1] == "﻿"):
                run_len = len(zw)
                sev = Severity.MEDIUM if run_len >= 3 else Severity.LOW
                names = sorted({_ZERO_WIDTH[ch] for _, ch in zw})
                yield Finding(
                    rule_id="CG503",
                    category="hidden-unicode",
                    severity=adjust_severity(sev, doc.context),
                    message=f"{run_len} zero-width / invisible character(s) "
                    f"({', '.join(names)}) on this line.",
                    path=doc.path,
                    line=lineno,
                    column=zw[0][0] + 1,
                    snippet=doc.snippet_for_line(lineno),
                    confidence="medium" if run_len >= 3 else "low",
                    reference="https://trojansource.codes/",
                    context=doc.context,
                    extra={"count": run_len},
                )

        # --- Private Use Area runs (variation-selector / PUA smuggling) ---
        pua = [i for i, ch in enumerate(line) if _in_pua(ch)]
        if len(pua) >= 4:
            yield Finding(
                rule_id="CG504",
                category="hidden-unicode",
                severity=adjust_severity(Severity.MEDIUM, doc.context),
                message=f"{len(pua)} Private Use Area code points on one line; "
                "used to hide encoded payloads inside otherwise-normal text.",
                path=doc.path,
                line=lineno,
                column=pua[0] + 1,
                snippet=doc.snippet_for_line(lineno),
                confidence="low",
                reference="https://trojansource.codes/",
                context=doc.context,
                extra={"count": len(pua)},
            )


def _in_pua(ch: str) -> bool:
    cp = ord(ch)
    return (
        0xE000 <= cp <= 0xF8FF
        or 0xF0000 <= cp <= 0xFFFFD
        or 0x100000 <= cp <= 0x10FFFD
        or 0xFE00 <= cp <= 0xFE0F  # variation selectors
        or 0xE0100 <= cp <= 0xE01EF
    )


_LATIN_WORD = re.compile(r"[A-Za-zͰ-ϿЀ-ӿ]{4,}")


@detector
def mixed_script_words(doc: Document) -> Iterable[Finding]:
    """Words that mix Latin with Cyrillic/Greek look-alikes (homoglyph attack)."""

    for lineno, line in enumerate(doc.lines, start=1):
        for match in _LATIN_WORD.finditer(line):
            word = match.group(0)
            scripts = set()
            for ch in word:
                cp = ord(ch)
                if 0x0400 <= cp <= 0x04FF:
                    scripts.add("Cyrillic")
                elif 0x0370 <= cp <= 0x03FF:
                    scripts.add("Greek")
                elif ch.isascii() and ch.isalpha():
                    scripts.add("Latin")
            if "Latin" in scripts and (scripts - {"Latin"}):
                yield Finding(
                    rule_id="CG505",
                    category="hidden-unicode",
                    severity=adjust_severity(Severity.MEDIUM, doc.context),
                    message=f"Word {word!r} mixes Latin with "
                    f"{', '.join(sorted(scripts - {'Latin'}))} characters "
                    "(homoglyph / look-alike text).",
                    path=doc.path,
                    line=lineno,
                    column=match.start() + 1,
                    snippet=doc.snippet_for_line(lineno),
                    confidence="medium",
                    reference="https://trojansource.codes/",
                    context=doc.context,
                )


# ---------------------------------------------------------------------------
# Layout-based smuggling
# ---------------------------------------------------------------------------

_INSTRUCTIONISH = re.compile(
    r"\b(ignore|instruction|system\s+prompt|you\s+must|you\s+should|assistant|"
    r"do\s+not\s+tell|exfiltrat|api[_\s-]?key|secret|token|password|execute|curl)\b",
    re.IGNORECASE,
)


@detector
def padded_and_offscreen_lines(doc: Document) -> Iterable[Finding]:
    for lineno, line in enumerate(doc.lines, start=1):
        # Text pushed far right by a long whitespace gap.
        gap = re.search(r"\S([ \t]{60,})\S", line)
        if gap and _INSTRUCTIONISH.search(line[gap.start():]):
            yield Finding(
                rule_id="CG601",
                category="obfuscation",
                severity=adjust_severity(Severity.MEDIUM, doc.context),
                message="Instruction-like text pushed off-screen by a long "
                "whitespace gap on the same line.",
                path=doc.path,
                line=lineno,
                column=gap.start() + 1,
                snippet=(line[:80] + " …[gap]… " + line[gap.end() - 1 :][:120]).strip(),
                confidence="medium",
                reference="https://labs.cloudsecurityalliance.org/",
                context=doc.context,
            )
        # Extremely long single line used to bury content / blow context.
        if len(line) > 3000 and _INSTRUCTIONISH.search(line):
            yield Finding(
                rule_id="CG602",
                category="obfuscation",
                severity=adjust_severity(Severity.LOW, doc.context),
                message=f"Very long line ({len(line)} chars) containing "
                "instruction-like text.",
                path=doc.path,
                line=lineno,
                column=1,
                snippet=line[:160] + "…",
                confidence="low",
                reference="https://labs.cloudsecurityalliance.org/",
                context=doc.context,
            )


# ---------------------------------------------------------------------------
# MCP configuration structure walk
# ---------------------------------------------------------------------------

_MCP_STRING_KEYS = {"description", "instructions", "instruction", "systemprompt", "prompt", "summary"}
_MCP_SUSPICIOUS = re.compile(
    r"<\s*IMPORTANT\s*>|before\s+(using|calling|invoking)\s+(any\s+)?(other\s+)?tool|"
    r"do\s+not\s+(tell|mention|inform)|ignore\s+(the\s+)?(above|previous)|"
    r"\.env|ssh\s+key|api[_\s-]?key|~/\.aws|read\s+the\s+file|system\s+prompt",
    re.IGNORECASE,
)
_PIPE_TO_SHELL = re.compile(r"curl\b[^\n|]*\|\s*(ba)?sh|wget\b[^\n|]*\|\s*(ba)?sh", re.IGNORECASE)


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"(^|\s)//[^\n]*", r"\1", text)
    return text


@detector
def mcp_config(doc: Document) -> Iterable[Finding]:
    if doc.context != CTX_MCP_CONFIG:
        return
    try:
        data = json.loads(_strip_jsonc(doc.raw_text))
    except (json.JSONDecodeError, ValueError):
        return

    for path_keys, value in _walk(data):
        key = path_keys[-1].lower() if path_keys else ""
        if isinstance(value, str):
            if key in _MCP_STRING_KEYS and _MCP_SUSPICIOUS.search(value):
                line = _find_line(doc, value)
                yield Finding(
                    rule_id="CG701",
                    category="mcp-tool-poisoning",
                    severity=adjust_severity(Severity.HIGH, doc.context),
                    message=f"MCP '{'.'.join(path_keys)}' field carries hidden "
                    "instructions / references to secrets — classic tool poisoning.",
                    path=doc.path,
                    line=line,
                    column=1,
                    snippet=_clip(value),
                    confidence="high",
                    reference="https://www.cve.org/CVERecord?id=CVE-2025-54136",
                    context=doc.context,
                    extra={"json_path": ".".join(path_keys)},
                )
            if key in {"command", "args"} or (key == "" and _PIPE_TO_SHELL.search(value)):
                if _PIPE_TO_SHELL.search(value):
                    line = _find_line(doc, value)
                    yield Finding(
                        rule_id="CG702",
                        category="mcp-tool-poisoning",
                        severity=adjust_severity(Severity.HIGH, doc.context),
                        message="MCP server launch command pipes a download into a shell.",
                        path=doc.path,
                        line=line,
                        column=1,
                        snippet=_clip(value),
                        confidence="high",
                        reference="https://www.cve.org/CVERecord?id=CVE-2025-54136",
                        context=doc.context,
                    )
        elif isinstance(value, list) and key == "args":
            joined = " ".join(str(v) for v in value)
            if _PIPE_TO_SHELL.search(joined):
                line = _find_line(doc, joined.split("|")[0].strip())
                yield Finding(
                    rule_id="CG702",
                    category="mcp-tool-poisoning",
                    severity=adjust_severity(Severity.HIGH, doc.context),
                    message="MCP server args pipe a download into a shell.",
                    path=doc.path,
                    line=line,
                    column=1,
                    snippet=_clip(joined),
                    confidence="high",
                    reference="https://www.cve.org/CVERecord?id=CVE-2025-54136",
                    context=doc.context,
                )


def _walk(obj, prefix=()):
    """Yield ``(path_tuple, value)`` for every string leaf and every list."""

    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, prefix + (str(k),))
    elif isinstance(obj, list):
        yield prefix, obj
        for i, v in enumerate(obj):
            yield from _walk(v, prefix + (f"[{i}]",))
    else:
        yield prefix, obj


@detector
def filename_tricks(doc: Document) -> Iterable[Finding]:
    """Filenames are concatenated into agent prompts by some tools."""

    name = doc.path.rsplit("/", 1)[-1]
    bad = {ch for ch in name if ch in _ZERO_WIDTH or ch in _BIDI or (ord(ch) < 32)}
    if bad:
        yield Finding(
            rule_id="CG801",
            category="filename-injection",
            severity=Severity.HIGH,
            message="Filename contains control / invisible / bidi characters.",
            path=doc.path,
            line=1,
            column=1,
            snippet=repr(name),
            confidence="high",
            reference="https://trojansource.codes/",
            context="filename",
        )
    stem = re.sub(r"[_\-.]+", " ", name)
    if _INSTRUCTIONISH.search(stem) and re.search(
        r"\b(ignore|you must|do not tell|system prompt|execute|curl)\b", stem, re.IGNORECASE
    ):
        yield Finding(
            rule_id="CG802",
            category="filename-injection",
            severity=Severity.MEDIUM,
            message="Filename reads like an instruction to an assistant.",
            path=doc.path,
            line=1,
            column=1,
            snippet=repr(name),
            confidence="medium",
            reference="https://labs.cloudsecurityalliance.org/",
            context="filename",
        )


def _find_line(doc: Document, needle: str) -> int:
    fragment = needle.strip().splitlines()[0][:40] if needle.strip() else ""
    if fragment:
        for lineno, line in enumerate(doc.lines, start=1):
            if fragment in line:
                return lineno
    return 1
