"""Reproduction metrics: success rate, validation rate, timing, false positives."""

from __future__ import annotations

from collections.abc import Iterable


def success_rate(statuses: Iterable[str]) -> float:
    items = list(statuses)
    if not items:
        return 0.0
    return sum(1 for s in items if s == "PASS") / len(items)


def false_positive_rate(predicted_pass: int, actual_vulnerable: int, total: int) -> float:
    """Placeholder definition — refine with the benchmark in Phase 7."""
    if total <= 0:
        return 0.0
    fp = max(0, predicted_pass - actual_vulnerable)
    return fp / total
