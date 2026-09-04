"""Core data types shared across ctxguard: :class:`Severity` and :class:`Finding`."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict


class Severity(IntEnum):
    """Ordered severity levels. Higher is worse; comparisons work as expected."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                + ", ".join(s.label for s in cls)
            ) from None


# Confidence is a coarse signal of how likely a finding is a true positive
# rather than an ordered gate, so it stays a plain string.
CONFIDENCE_LEVELS = ("low", "medium", "high")


@dataclass(frozen=True)
class Finding:
    """A single suspicious location in a scanned file."""

    rule_id: str
    category: str
    severity: Severity
    message: str
    path: str
    line: int
    column: int = 1
    snippet: str = ""
    confidence: str = "medium"
    reference: str = ""
    context: str = "generic"  # e.g. "agent-instructions", "mcp-config", "filename"
    extra: Dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple:
        # Most severe first, then by location for stable output.
        return (-int(self.severity), self.path, self.line, self.column, self.rule_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.label,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "confidence": self.confidence,
            "reference": self.reference,
            "context": self.context,
            "extra": dict(self.extra),
        }
