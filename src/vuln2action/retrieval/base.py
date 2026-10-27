"""Shared retrieval backend interface and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vuln2action.domain import KnowledgeDocument, RetrievedContext


class RetrievalBackend(ABC):
    """A backend scores documents for a query and returns typed contexts."""

    name = "base"

    @abstractmethod
    def search(
        self,
        query: str,
        documents: list[KnowledgeDocument],
        top_k: int = 3,
    ) -> list[RetrievedContext]:
        raise NotImplementedError


def get_backend(name: str) -> RetrievalBackend:
    key = (name or "keyword").strip().lower()
    if key in {"keyword", "kw"}:
        from vuln2action.retrieval.keyword import KeywordBackend

        return KeywordBackend()
    if key in {"tfidf", "tf-idf"}:
        from vuln2action.retrieval.tfidf import TfidfBackend

        return TfidfBackend()
    if key in {"semantic", "enriched"}:
        from vuln2action.retrieval.semantic import SemanticBackend

        return SemanticBackend()
    if key in {"embedding", "embeddings"}:
        raise NotImplementedError(
            "Neural embedding retrieval is not configured. Use keyword, TF-IDF, or "
            "semantic (MITRE-enriched lexical) retrieval."
        )
    raise ValueError(f"Unknown retrieval backend: {name!r}")
