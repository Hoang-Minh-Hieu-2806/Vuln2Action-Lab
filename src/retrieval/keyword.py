"""Keyword retrieval baseline (no external dependencies).

TODO(Phase 3): evaluate against TF-IDF on a local corpus.
"""
from __future__ import annotations

import re


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def keyword_score(query: str, document: str) -> float:
    """Simple overlap score in [0, 1]."""
    q, d = _tokens(query), _tokens(document)
    if not q:
        return 0.0
    return len(q & d) / len(q)


def keyword_search(query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
    """Return (doc_index, score) pairs sorted by score desc. TODO: richer ranking."""
    scored = [(i, keyword_score(query, doc)) for i, doc in enumerate(documents)]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]
