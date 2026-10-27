"""TF-IDF retrieval baseline with an explicit lightweight fallback."""


def tfidf_search(query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        from vuln2action.retrieval.keyword import keyword_search

        return keyword_search(query, documents, top_k=top_k)
    if not documents:
        return []
    vectorizer = TfidfVectorizer()
    document_matrix = vectorizer.fit_transform(documents)
    query_vector = vectorizer.transform([query])
    similarities = cosine_similarity(query_vector, document_matrix)[0]
    ranked = sorted(
        enumerate(float(score) for score in similarities),
        key=lambda item: item[1],
        reverse=True,
    )
    return ranked[:top_k]
