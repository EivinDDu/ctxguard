"""Score ctxsentry against a labelled corpus.

The corpus lives in ``benchmark/`` at the repo root: ``cases.jsonl`` lists each
fixture with a label (``malicious`` / ``benign``) and, for malicious cases, the
rule id that *should* fire. ``run_benchmark`` scans every fixture and returns
precision / recall / F1 / false-positive-rate plus a list of the individual
mismatches, so "is it better?" has a number behind it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ctxsentry.scanner import ScanConfig, scan

DEFAULT_BENCH_DIR = Path(__file__).resolve().parents[2] / "benchmark"


@dataclass(frozen=True)
class Case:
    path: str
    label: str  # "malicious" | "benign"
    expect_rule: Optional[str] = None
    note: str = ""


@dataclass
class BenchResult:
    tp: int = 0  # malicious, flagged
    fn: int = 0  # malicious, missed
    fp: int = 0  # benign, flagged
    tn: int = 0  # benign, clean
    rule_expected: int = 0
    rule_hit: int = 0  # malicious case where the *named* rule fired
    misses: List[tuple] = field(default_factory=list)  # (case, reason)

    @property
    def total(self) -> int:
        return self.tp + self.fn + self.fp + self.tn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fp_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def rule_accuracy(self) -> float:
        return self.rule_hit / self.rule_expected if self.rule_expected else 1.0

    def to_dict(self) -> dict:
        return {
            "counts": {"tp": self.tp, "fn": self.fn, "fp": self.fp, "tn": self.tn},
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fp_rate": round(self.fp_rate, 4),
            "rule_accuracy": round(self.rule_accuracy, 4),
            "misses": [{"path": c.path, "reason": reason} for c, reason in self.misses],
        }


def load_cases(bench_dir: Path = DEFAULT_BENCH_DIR) -> List[Case]:
    manifest = bench_dir / "cases.jsonl"
    cases: List[Case] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cases.append(Case(**json.loads(line)))
    return cases


def run_benchmark(bench_dir: Path = DEFAULT_BENCH_DIR) -> BenchResult:
    res = BenchResult()
    for case in load_cases(bench_dir):
        target = (bench_dir / case.path).resolve()
        findings = scan(ScanConfig(root=target)).findings
        rule_ids = {f.rule_id for f in findings}

        if case.label == "malicious":
            if findings:
                res.tp += 1
            else:
                res.fn += 1
                res.misses.append((case, "false negative: no finding"))
            if case.expect_rule:
                res.rule_expected += 1
                if case.expect_rule in rule_ids:
                    res.rule_hit += 1
                else:
                    got = ", ".join(sorted(rule_ids)) or "nothing"
                    res.misses.append(
                        (case, f"expected {case.expect_rule}, got {got}")
                    )
        else:
            if findings:
                res.fp += 1
                res.misses.append(
                    (case, "false positive: " + ", ".join(sorted(rule_ids)))
                )
            else:
                res.tn += 1
    return res
