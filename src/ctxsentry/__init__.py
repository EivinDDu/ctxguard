"""ctxsentry - inbound prompt-injection scanner for AI coding agents.

ctxsentry inspects the files an AI coding agent ingests the moment it opens a
repository (READMEs, docs, issue text, agent rule files, ``.mcp.json`` tool
descriptions, filenames) and reports content that looks engineered to hijack
the agent: instruction overrides, invisible Unicode, HTML smuggling, and
data-exfiltration primitives.
"""

from ctxsentry.finding import Finding, Severity

__version__ = "0.4.0"
__all__ = ["Finding", "Severity", "__version__"]
