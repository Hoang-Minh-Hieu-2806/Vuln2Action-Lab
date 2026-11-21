"""TF-IDF + cosine best-CAPEC selection."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from vuln2action.domain import CapecRecord
from vuln2action.mapping.corpus import capec_selection_text
from vuln2action.mapping.ranking import best_candidate
from vuln2action.retrieval.text import STOPWORDS


class TfidfCapecSelector:
    """Rank candidate CAPECs by lexical cosine similarity to a CVE description."""

    method = "tfidf"

    def __init__(
        self,
        capecs: Mapping[str, CapecRecord],
        background_texts: Iterable[str] = (),
        ngram_range: tuple[int, int] = (1, 2),
    ) -> None:
        if not capecs:
            raise ValueError("capecs must not be empty")
        self._capec_ids = sorted(capecs)
        self._index = {capec_id: index for index, capec_id in enumerate(self._capec_ids)}
        capec_texts = [capec_selection_text(capecs[capec_id]) for capec_id in self._capec_ids]
        corpus = capec_texts + [text.strip() for text in background_texts if text.strip()]
        self._vectorizer = TfidfVectorizer(
            ngram_range=ngram_range,
            sublinear_tf=True,
            stop_words=sorted(STOPWORDS),
            token_pattern=r"(?u)\b\w+\b",
        )
        self._vectorizer.fit(corpus)
        self._matrix = self._vectorizer.transform(capec_texts)

    @property
    def capec_ids(self) -> tuple[str, ...]:
        return tuple(self._capec_ids)

    def scores(self, query: str, candidate_ids: Iterable[str]) -> dict[str, float]:
        """Cosine score for each known candidate; unknown ids are ignored."""
        known = sorted(
            {capec_id for capec_id in candidate_ids if capec_id in self._index},
            key=lambda capec_id: self._index[capec_id],
        )
        if not known:
            return {}
        indices = [self._index[capec_id] for capec_id in known]
        query_vector = self._vectorizer.transform([query])
        similarities = cosine_similarity(query_vector, self._matrix[indices])[0]
        return {capec_id: float(score) for capec_id, score in zip(known, similarities, strict=True)}

    def select(self, query: str, candidate_ids: Iterable[str]) -> tuple[str | None, float]:
        return best_candidate(self.scores(query, candidate_ids))
