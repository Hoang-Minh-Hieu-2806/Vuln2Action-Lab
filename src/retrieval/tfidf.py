"""TF-IDF retrieval baseline (requires scikit-learn, else falls back).

TODO(Phase 3): benchmark vs keyword in evaluation/retrieval/.
"""
from __future__ import annotations


def tfidf_search(query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
    """Rank documents with TF-IDF cosine similarity.

    Falls back to keyword search when sklearn is unavailable.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        from src.retrieval.keyword import keyword_search

        return keyword_search(query, documents, top_k=top_k)
    if not documents:
        return []
    vectorizer = TfidfVectorizer()
    doc_matrix = vectorizer.fit_transform(documents)
    q_vec = vectorizer.transform([query])
    sims = cosine_similarity(q_vec, doc_matrix)[0]
    ranked = sorted(enumerate(float(s) for s in sims), key=lambda x: x[1], reverse=True)
    return ranked[:top_k]
