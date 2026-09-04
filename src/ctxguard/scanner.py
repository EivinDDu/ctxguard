"""Walk a path, decode candidate files, and run every detector over them."""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from ctxguard.contexts import (
    CTX_VCS_META,
    DEFAULT_EXCLUDE_DIRS,
    TEXT_EXTENSIONS,
    classify,
)
from ctxguard.detectors import all_detectors, invisible_unicode, run_rules
from ctxguard.document import Document
from ctxguard.finding import Finding, Severity

DEFAULT_MAX_BYTES = 1_000_000


@dataclass
class ScanConfig:
    root: Path
    max_bytes: int = DEFAULT_MAX_BYTES
    exclude_dirs: frozenset = DEFAULT_EXCLUDE_DIRS
    follow_symlinks: bool = False
    scan_all_text: bool = False  # scan any UTF-8 text file, not just known contexts
    include_git_history: bool = False
    git_history_limit: int = 200


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)

    def counts_by_severity(self) -> dict:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    return False


def _decode(data: bytes) -> Optional[str]:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def _should_consider(rel_path: str, config: ScanConfig) -> bool:
    ext = os.path.splitext(rel_path)[1].lower()
    if classify(rel_path) != "generic":
        return True
    if config.scan_all_text:
        return ext in TEXT_EXTENSIONS or ext in {".py", ".js", ".ts", ".sh", ".rb", ".go"}
    return ext in TEXT_EXTENSIONS


def iter_files(config: ScanConfig) -> Iterable[Path]:
    root = config.root
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=config.follow_symlinks):
        dirnames[:] = sorted(d for d in dirnames if d not in config.exclude_dirs)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _rel(path: Path, config: ScanConfig) -> str:
    root = config.root if config.root.is_dir() else config.root.parent
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _load_ignore_file(config: ScanConfig) -> List[tuple]:
    """Parse ``.ctxguardignore`` at the scan root.

    Each non-comment line is ``path-glob`` or ``path-glob:RULE1,RULE2``. A bare
    glob suppresses every rule for matching files.
    """

    root = config.root if config.root.is_dir() else config.root.parent
    ignore_path = root / ".ctxguardignore"
    entries: List[tuple] = []
    try:
        raw = ignore_path.read_text(encoding="utf-8")
    except OSError:
        return entries
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        glob, _, rule_part = line.partition(":")
        rule_ids = frozenset(r.strip().upper() for r in rule_part.split(",") if r.strip())
        entries.append((glob.strip(), rule_ids))
    return entries


def _ignored(rel_path: str, rule_id: str, entries: List[tuple]) -> bool:
    for glob, rule_ids in entries:
        if fnmatch.fnmatch(rel_path, glob) and (not rule_ids or rule_id.upper() in rule_ids):
            return True
    return False


def scan(config: ScanConfig) -> ScanResult:
    result = ScanResult()
    detectors = all_detectors()
    ignore_entries = _load_ignore_file(config)

    for path in iter_files(config):
        rel = _rel(path, config)
        if not _should_consider(rel, config):
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            result.errors.append(f"{rel}: {exc}")
            continue
        if len(data) > config.max_bytes or _looks_binary(data):
            result.files_skipped += 1
            continue
        text = _decode(data)
        if text is None:
            result.files_skipped += 1
            continue

        doc = Document(
            path=rel,
            abs_path=str(path),
            context=classify(rel),
            raw_text=text,
        )
        result.files_scanned += 1
        doc_findings: List[Finding] = []
        for det in detectors:
            try:
                doc_findings.extend(det(doc))
            except Exception as exc:  # pragma: no cover - defensive
                result.errors.append(f"{rel}: detector {det.__name__} failed: {exc}")
        doc_findings = [
            f for f in doc_findings if not _ignored(rel, f.rule_id, ignore_entries)
        ]
        result.findings.extend(_apply_suppressions(doc, doc_findings))

    if config.include_git_history:
        _scan_git_history(config, result)

    result.findings.sort(key=Finding.sort_key)
    return result


# Suppress a finding by putting `ctxguard: ignore` (optionally with rule ids) on
# the flagged line or the line immediately above it.
_SUPPRESS_RE = re.compile(
    r"ctxguard:\s*(?:ignore|allow|disable|nosec)\b[ \t]*([A-Za-z0-9, ]*)",
    re.IGNORECASE,
)


def _apply_suppressions(doc: Document, findings: List[Finding]) -> List[Finding]:
    if not findings:
        return findings
    # line number -> set of rule ids (empty set == suppress everything on that line)
    directives: dict = {}
    for lineno, line in enumerate(doc.lines, start=1):
        m = _SUPPRESS_RE.search(line)
        if m:
            ids = {tok.strip().upper() for tok in m.group(1).split(",") if tok.strip()}
            directives[lineno] = ids

    kept = []
    for f in findings:
        suppressed = False
        for target in (f.line, f.line - 1):
            if target in directives:
                ids = directives[target]
                if not ids or f.rule_id.upper() in ids:
                    suppressed = True
                    break
        if not suppressed:
            kept.append(f)
    return kept


def _scan_git_history(config: ScanConfig, result: ScanResult) -> None:
    """Run the text/Unicode detectors over recent commit messages.

    Commit messages, like issue and PR bodies, are attacker-influenced text that
    coding agents frequently read.
    """

    root = config.root if config.root.is_dir() else config.root.parent
    if not (root / ".git").exists():
        return
    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "log",
                f"-{config.git_history_limit}",
                "--no-color",
                "--format=%H%x00%B%x1e",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        result.errors.append(f"git history: {exc}")
        return

    for record in out.split("\x1e"):
        record = record.strip("\n")
        if not record or "\x00" not in record:
            continue
        sha, body = record.split("\x00", 1)
        doc = Document(
            path=f"git:commit/{sha[:10]}",
            abs_path=str(root),
            context=CTX_VCS_META,
            raw_text=body,
        )
        for det in (run_rules, invisible_unicode):
            try:
                result.findings.extend(det(doc))
            except Exception as exc:  # pragma: no cover - defensive
                result.errors.append(f"git history {sha[:10]}: {exc}")


def scan_path(
    target: os.PathLike | str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    scan_all_text: bool = False,
    include_git_history: bool = False,
    extra_excludes: Sequence[str] = (),
) -> ScanResult:
    """Convenience wrapper used by the CLI and tests."""

    excludes = DEFAULT_EXCLUDE_DIRS | set(extra_excludes)
    config = ScanConfig(
        root=Path(target).resolve(),
        max_bytes=max_bytes,
        exclude_dirs=frozenset(excludes),
        scan_all_text=scan_all_text,
        include_git_history=include_git_history,
    )
    return scan(config)
