"""Dependency-free keyword baseline with stopword filtering and Dice overlap."""

from vuln2action.domain import KnowledgeDocument, RetrievedContext
from vuln2action.retrieval.base import RetrievalBackend
from vuln2action.retrieval.text import tokenize


def keyword_score(query: str, document: str) -> float:
    """Dice similarity over stopword-filtered content-token sets."""
    query_tokens = set(tokenize(query))
    document_tokens = set(tokenize(document))
    if not query_tokens or not document_tokens:
        return 0.0
    overlap = len(query_tokens & document_tokens)
    return 2 * overlap / (len(query_tokens) + len(document_tokens))


def keyword_search(query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
    scored: list[tuple[int, float]] = []
    for index, document in enumerate(documents):
        score = keyword_score(query, document)
        if score > 0.0:
            scored.append((index, score))
    return sorted(scored, key=lambda item: item[1], reverse=True)[:top_k]


class KeywordBackend(RetrievalBackend):
    name = "keyword"

    def search(
        self,
        query: str,
        documents: list[KnowledgeDocument],
        top_k: int = 3,
    ) -> list[RetrievedContext]:
        texts = [document.text for document in documents]
        hits = keyword_search(query, texts, top_k=top_k)
        return [
            RetrievedContext(
                source=documents[index].doc_id,
                text=documents[index].text,
                score=score,
                backend=self.name,
            )
            for index, score in hits
        ]
