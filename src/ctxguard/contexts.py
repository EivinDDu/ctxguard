"""Classify scanned paths by how an AI coding agent treats them.

The same payload is far more dangerous in a file an agent loads automatically as
standing instructions (``CLAUDE.md``, ``.cursorrules``, ``.mcp.json``) than in an
arbitrary source file, so detectors use the context to boost severity.
"""

from __future__ import annotations

import fnmatch
import posixpath
from typing import Iterable

# Contexts, most-trusted-by-agents first.
CTX_MCP_CONFIG = "mcp-config"
CTX_AGENT_INSTRUCTIONS = "agent-instructions"
CTX_AGENT_SKILL = "agent-skill"
CTX_DOCS = "docs"
CTX_VCS_META = "vcs-metadata"  # commit messages, issue/PR bodies fed in via history
CTX_GENERIC = "generic"

# Files agents ingest automatically as authoritative instructions.
_AGENT_INSTRUCTION_GLOBS = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/*.md",
    ".claude/**/*.md",
    "AGENTS.md",
    "AGENT.md",
    "GEMINI.md",
    ".gemini/*.md",
    ".cursorrules",
    ".cursor/rules/*",
    ".cursor/rules/**/*",
    ".windsurfrules",
    ".windsurf/rules/*",
    ".clinerules",
    ".clinerules/*",
    ".aider.conf.yml",
    ".aider/*",
    ".github/copilot-instructions.md",
    ".github/instructions/*",
    ".continue/*",
)

_MCP_CONFIG_GLOBS = (
    ".mcp.json",
    "mcp.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    "**/mcp.json",
    "**/.mcp.json",
)

_AGENT_SKILL_GLOBS = (
    "SKILL.md",
    "skill.md",
    "**/SKILL.md",
    ".claude/skills/**/*",
    "skills/**/*.md",
)

_DOCS_GLOBS = (
    "README*",
    "readme*",
    "CONTRIBUTING*",
    "SECURITY*",
    "docs/*",
    "docs/**/*",
    "*.md",
    "*.mdx",
    "*.rst",
    "*.txt",
)

# Directories that never carry agent context and bloat scans.
DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env.d",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".gradle",
        ".idea",
    }
)

# Extensions we treat as scannable text regardless of name.
TEXT_EXTENSIONS = frozenset(
    {
        ".md",
        ".mdx",
        ".markdown",
        ".rst",
        ".txt",
        ".json",
        ".jsonc",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".xml",
        ".html",
        ".htm",
        ".csv",
        ".tsv",
        ".rules",
        ".mdc",
        "",  # dotfiles like .cursorrules
    }
)


def _match_any(rel_path: str, globs: Iterable[str]) -> bool:
    name = posixpath.basename(rel_path)
    for pattern in globs:
        if "/" in pattern:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
        elif fnmatch.fnmatch(name, pattern):
            return True
    return False


def classify(rel_path: str) -> str:
    """Return the context constant for a repo-relative POSIX path."""

    rel_path = rel_path.replace("\\", "/").lstrip("./")
    if _match_any(rel_path, _MCP_CONFIG_GLOBS):
        return CTX_MCP_CONFIG
    if _match_any(rel_path, _AGENT_INSTRUCTION_GLOBS):
        return CTX_AGENT_INSTRUCTIONS
    if _match_any(rel_path, _AGENT_SKILL_GLOBS):
        return CTX_AGENT_SKILL
    if _match_any(rel_path, _DOCS_GLOBS):
        return CTX_DOCS
    return CTX_GENERIC


# How much to bump a rule's base severity for a given context (in levels).
CONTEXT_SEVERITY_BOOST = {
    CTX_MCP_CONFIG: 2,
    CTX_AGENT_INSTRUCTIONS: 2,
    CTX_AGENT_SKILL: 1,
    CTX_DOCS: 1,
    CTX_VCS_META: 1,
    CTX_GENERIC: 0,
}
