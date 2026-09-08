"""The unit of work passed to every detector: one decoded text file."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import List, Tuple


@dataclass
class Document:
    """A single scannable file, already decoded to text.

    ``raw_text`` keeps the original characters (including invisible ones) so the
    Unicode detectors can see what a normal editor would hide.
    """

    path: str  # display path (repo-relative, POSIX separators)
    abs_path: str
    context: str
    raw_text: str

    @cached_property
    def lines(self) -> List[str]:
        return self.raw_text.splitlines()

    @cached_property
    def _line_starts(self) -> List[int]:
        starts = [0]
        for line in self.raw_text.splitlines(keepends=True):
            starts.append(starts[-1] + len(line))
        return starts

    def locate(self, offset: int) -> Tuple[int, int]:
        """Map a character offset to a 1-based ``(line, column)`` pair."""

        starts = self._line_starts
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - starts[lo] + 1

    def snippet_for_line(self, line_no: int, limit: int = 200) -> str:
        if 1 <= line_no <= len(self.lines):
            text = self.lines[line_no - 1].strip()
            if len(text) > limit:
                text = text[:limit] + "…"
            return text
        return ""
