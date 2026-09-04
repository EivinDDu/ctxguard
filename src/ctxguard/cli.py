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


def _run_rules() -> int:
    for rule in sorted(RULES, key=lambda r: r.id):
        print(f"{rule.id}  {rule.base_severity.label:<8} {rule.category}")
        print(f"      {rule.message}")
    print(f"\n{len(RULES)} regex rules (plus Unicode, layout, MCP and filename detectors).")
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
