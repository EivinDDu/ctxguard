"""Command-line entry point for ctxguard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from ctxguard import __version__
from ctxguard.finding import Severity
from ctxguard.report import render
from ctxguard.rules import RULES
from ctxguard.scanner import DEFAULT_MAX_BYTES, ScanConfig, scan

_EPILOG = """\
exit codes:
  0  scan completed, nothing at or above --fail-on
  1  findings at or above --fail-on severity
  2  usage / runtime error

examples:
  ctxguard scan .
  ctxguard scan ../some-repo --format sarif -o ctxguard.sarif
  ctxguard scan . --fail-on medium --git-history
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctxguard",
        description=(
            "Scan a repository for prompt-injection payloads before you point "
            "an AI coding agent at it."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"ctxguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a path", description="Scan a file or directory.")
    scan_p.add_argument("path", nargs="?", default=".", help="file or directory (default: .)")
    scan_p.add_argument(
        "-f",
        "--format",
        default="text",
        choices=["text", "json", "sarif", "markdown"],
        help="output format (default: text)",
    )
    scan_p.add_argument("-o", "--output", help="write report to this file instead of stdout")
    scan_p.add_argument(
        "--fail-on",
        default="high",
        choices=[s.label for s in Severity] + ["none"],
        help="exit 1 if any finding is at least this severe (default: high)",
    )
    scan_p.add_argument(
        "--min-severity",
        default="low",
        choices=[s.label for s in Severity],
        help="hide findings below this severity (default: low)",
    )
    scan_p.add_argument(
        "--min-confidence",
        default="low",
        choices=["low", "medium", "high"],
        help="hide findings below this confidence (default: low)",
    )
    scan_p.add_argument(
        "--all-text",
        action="store_true",
        help="scan every UTF-8 text/source file, not just known agent-context files",
    )
    scan_p.add_argument(
        "--git-history",
        action="store_true",
        help="also scan recent git commit messages",
    )
    scan_p.add_argument(
        "--changed",
        nargs="?",
        const="HEAD",
        default=None,
        metavar="REF",
        help="scan only files changed vs REF (default: HEAD) plus staged/unstaged/"
        "untracked — fast pre-commit and PR gating",
    )
    scan_p.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"skip files larger than this (default: {DEFAULT_MAX_BYTES})",
    )
    scan_p.add_argument("--exclude", action="append", default=[], metavar="DIR", help="extra directory name to skip (repeatable)")
    scan_p.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    sub.add_parser("rules", help="list detection rules")

    return parser


_CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


def _run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"ctxguard: path not found: {target}", file=sys.stderr)
        return 2

    config = ScanConfig(
        root=target.resolve(),
        max_bytes=args.max_bytes,
        scan_all_text=args.all_text,
        include_git_history=args.git_history,
        changed_since=args.changed,
    )
    if args.exclude:
        config.exclude_dirs = frozenset(config.exclude_dirs | set(args.exclude))

    result = scan(config)

    min_sev = Severity.parse(args.min_severity)
    min_conf = _CONF_ORDER[args.min_confidence]
    result.findings = [
        f
        for f in result.findings
        if f.severity >= min_sev and _CONF_ORDER[f.confidence] >= min_conf
    ]

    report = render(result, args.format, color=not args.no_color and _stdout_is_tty(args))
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"ctxguard: wrote {len(result.findings)} finding(s) to {args.output}")
    else:
        print(report)

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    worst = result.max_severity()
    return 1 if worst is not None and worst >= threshold else 0


def _stdout_is_tty(args: argparse.Namespace) -> bool:
    return sys.stdout.isatty() and not args.output


_EXTRA_RULES = [
    ("CG403", "low", "obfuscation", "Long base64 blob that does not decode to readable text."),
    ("CG404", "high", "obfuscation", "base64 / hex blob decodes to instruction or secret-like text."),
    ("CG501", "high", "hidden-unicode", "Unicode Tag characters (U+E00xx); decoded and reported."),
    ("CG502", "high", "hidden-unicode", "Bidirectional control character (Trojan Source)."),
    ("CG503", "low", "hidden-unicode", "Zero-width / invisible character run."),
    ("CG504", "medium", "hidden-unicode", "Private Use Area code-point run."),
    ("CG505", "medium", "hidden-unicode", "Word mixes Latin with Cyrillic/Greek look-alikes."),
    ("CG601", "medium", "obfuscation", "Instruction-like text pushed off-screen by a whitespace gap."),
    ("CG602", "low", "obfuscation", "Very long line containing instruction-like text."),
    ("CG701", "high", "mcp-tool-poisoning", "MCP tool description carries hidden instructions."),
    ("CG702", "high", "mcp-tool-poisoning", "MCP server launch command pipes a download into a shell."),
    ("CG801", "high", "filename-injection", "Filename contains control / invisible / bidi characters."),
    ("CG802", "medium", "filename-injection", "Filename reads like an instruction to an assistant."),
]


def _run_rules() -> int:
    rows = [(r.id, r.base_severity.label, r.category, r.message) for r in RULES]
    rows += _EXTRA_RULES
    for rid, sev, cat, msg in sorted(rows):
        print(f"{rid}  {sev:<8} {cat}")
        print(f"      {msg}")
    print(
        f"\n{len(RULES)} regex rules + {len(_EXTRA_RULES)} analytic detectors "
        "(encoded-payload, Unicode, layout, MCP, filename)."
    )
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "rules":
            return _run_rules()
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    parser.error("unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
