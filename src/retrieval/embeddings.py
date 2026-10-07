"""Embedding retrieval stub (Phase 3+, optional).

TODO(Phase 3): implement only if keyword/TF-IDF baselines underperform.
Keep heavy deps (sentence-transformers/torch) OPTIONAL and out of requirements.
"""
from __future__ import annotations


class EmbeddingRetriever:
    """Placeholder embedding retriever."""

    def __init__(self, model_name: str = "") -> None:
        self.model_name = model_name

    def search(self, query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
        raise NotImplementedError(
            "Embedding retrieval is not implemented in Phase 1. "
            "Use keyword_search or tfidf_search instead."
        )
