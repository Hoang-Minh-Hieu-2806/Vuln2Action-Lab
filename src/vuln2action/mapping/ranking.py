"""Deterministic ordering helpers shared by the CAPEC selectors."""

from __future__ import annotations

import re

_NUMBER = re.compile(r"(\d+)")


def capec_sort_key(capec_id: str) -> tuple[int, str]:
    match = _NUMBER.search(capec_id)
    number = int(match.group(1)) if match else 0
    return number, capec_id


def best_candidate(scores: dict[str, float]) -> tuple[str | None, float]:
    """Return the highest-scoring candidate, breaking ties by CAPEC number."""
    if not scores:
        return None, 0.0
    selected = min(scores, key=lambda capec_id: (-scores[capec_id], capec_sort_key(capec_id)))
    return selected, float(scores[selected])
