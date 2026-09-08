"""Guard rails for the distribution: version consistency and metadata."""

from __future__ import annotations

import pathlib
import re

import ctxsentry

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_version_matches_pyproject():
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', PYPROJECT)
    assert m and m.group(1) == ctxsentry.__version__


def test_console_script_is_the_cli_entrypoint():
    assert 'ctxsentry = "ctxsentry.cli:main"' in PYPROJECT


def test_changelog_documents_current_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"[{ctxsentry.__version__}]" in changelog


def test_no_stale_ctxguard_references_in_source():
    for path in (ROOT / "src").rglob("*.py"):
        assert "ctxguard" not in path.read_text(encoding="utf-8"), path
