"""Dependency-free keyword baseline."""

import re


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def keyword_score(query: str, document: str) -> float:
    query_tokens, document_tokens = _tokens(query), _tokens(document)
    if not query_tokens:
        return 0.0
    return len(query_tokens & document_tokens) / len(query_tokens)


def keyword_search(query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
    scored = [(index, keyword_score(query, document)) for index, document in enumerate(documents)]
    return sorted(scored, key=lambda item: item[1], reverse=True)[:top_k]
