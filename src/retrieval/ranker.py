"""Ranker: merge/dedupe results from multiple retrieval backends."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RetrievedContext:
    """One retrieved knowledge snippet."""

    source: str  # e.g. "CWE-79", "CAPEC-63", "reference:https://..."
    text: str
    score: float = 0.0
    backend: str = "keyword"

    def to_dict(self) -> dict[str, object]:
        return {"source": self.source, "text": self.text, "score": self.score, "backend": self.backend}


def rank_contexts(contexts: list[RetrievedContext], top_k: int = 3) -> list[RetrievedContext]:
    """Dedupe by source (keep max score) and return top-k by score."""
    best: dict[str, RetrievedContext] = {}
    for ctx in contexts:
        prev = best.get(ctx.source)
        if prev is None or ctx.score > prev.score:
            best[ctx.source] = ctx
    ranked = sorted(best.values(), key=lambda c: c.score, reverse=True)
    return ranked[:top_k]


def build_contexts_for_cve(cve: object, top_k: int = 3) -> list[RetrievedContext]:
    """Build offline contexts from CWE lookup + references (no network).

    TODO(Phase 3): replace with corpus search over local knowledge base.
    """
    from src.ingestion.cwe import lookup_cwe

    contexts: list[RetrievedContext] = []
    for cwe_id in getattr(cve, "cwe", []):
        record = lookup_cwe(cwe_id)
        if record is not None:
            contexts.append(
                RetrievedContext(
                    source=record.cwe_id,
                    text=f"{record.cwe_id} {record.name}: {record.description}",
                    score=1.0,
                    backend="cwe-lookup",
                )
            )
    for url in getattr(cve, "references", []):
        contexts.append(
            RetrievedContext(source=f"reference:{url}", text=f"Reference: {url}", score=0.5)
        )
    return rank_contexts(contexts, top_k=top_k)
