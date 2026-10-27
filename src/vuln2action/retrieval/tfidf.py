"""TF-IDF retrieval baseline with word bigrams and title field weighting."""

from vuln2action.domain import KnowledgeDocument, RetrievedContext
from vuln2action.retrieval.base import RetrievalBackend
from vuln2action.retrieval.text import STOPWORDS, document_text

_STOP_WORDS = sorted(STOPWORDS)


def tfidf_search(query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        from vuln2action.retrieval.keyword import keyword_search

        return keyword_search(query, documents, top_k=top_k)
    if not documents:
        return []
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words=_STOP_WORDS,
        token_pattern=r"(?u)\b\w+\b",
    )
    document_matrix = vectorizer.fit_transform(documents)
    query_vector = vectorizer.transform([query])
    similarities = cosine_similarity(query_vector, document_matrix)[0]
    ranked = [(index, float(score)) for index, score in enumerate(similarities) if score > 0.0]
    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked[:top_k]


class TfidfBackend(RetrievalBackend):
    name = "tfidf"

    def __init__(self, name_weight: int = 2) -> None:
        if name_weight < 1:
            raise ValueError("name_weight must be at least 1")
        self.name_weight = name_weight

    def search(
        self,
        query: str,
        documents: list[KnowledgeDocument],
        top_k: int = 3,
    ) -> list[RetrievedContext]:
        texts = [document_text(document, self.name_weight) for document in documents]
        hits = tfidf_search(query, texts, top_k=top_k)
        return [
            RetrievedContext(
                source=documents[index].doc_id,
                text=documents[index].text,
                score=score,
                backend=self.name,
            )
            for index, score in hits
        ]
