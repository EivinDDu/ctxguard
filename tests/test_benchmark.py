"""The benchmark corpus doubles as a regression gate: detection must stay at
100% recall / 0 false positives / every malicious case hitting its named rule.
If a change regresses that, this test fails before CI's `ctxsentry bench` does.
"""

from __future__ import annotations

from ctxsentry.benchmark import DEFAULT_BENCH_DIR, load_cases, run_benchmark


def test_corpus_manifest_matches_files():
    for case in load_cases():
        assert (DEFAULT_BENCH_DIR / case.path).is_file(), case.path
        assert case.label in {"malicious", "benign"}


def test_benchmark_is_green():
    res = run_benchmark()
    assert res.total >= 30
    assert res.recall == 1.0, res.to_dict()["misses"]
    assert res.fp_rate == 0.0, res.to_dict()["misses"]
    assert res.rule_accuracy == 1.0, res.to_dict()["misses"]
