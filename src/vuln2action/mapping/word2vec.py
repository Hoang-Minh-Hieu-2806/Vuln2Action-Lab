"""Word2Vec + cosine best-CAPEC selection.

Word2Vec is optional: install the ``nlp`` extra (or ``gensim``) before using
this selector. The selector averages word vectors into a sentence vector and
compares it with each candidate CAPEC's sentence vector.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

import numpy as np

from vuln2action.domain import CapecRecord
from vuln2action.mapping.corpus import capec_selection_text
from vuln2action.mapping.ranking import best_candidate
from vuln2action.retrieval.text import split_camel_case, tokenize


class Word2VecCapecSelector:
    """Rank candidate CAPECs with a Word2Vec model trained on the local corpus."""

    method = "word2vec"

    def __init__(
        self,
        capecs: Mapping[str, CapecRecord],
        background_texts: Iterable[str] = (),
        vector_size: int = 100,
        window: int = 5,
        epochs: int = 10,
        seed: int = 42,
        workers: int = 1,
    ) -> None:
        if not capecs:
            raise ValueError("capecs must not be empty")
        if vector_size < 1 or window < 1 or epochs < 1 or workers < 1:
            raise ValueError("vector_size, window, epochs, and workers must be positive")
        try:
            from gensim.models import Word2Vec
        except ImportError as exc:
            raise RuntimeError(
                "Word2Vec selection requires gensim; install it with "
                '`pip install -e ".[nlp]"` or `pip install "gensim>=4.3"`.'
            ) from exc

        self._capec_ids = sorted(capecs)
        self._order = {capec_id: index for index, capec_id in enumerate(self._capec_ids)}
        capec_texts = {
            capec_id: capec_selection_text(capecs[capec_id]) for capec_id in self._capec_ids
        }
        sentences = [
            tokenize(split_camel_case(text))
            for text in list(background_texts) + list(capec_texts.values())
            if text.strip()
        ]
        sentences = [sentence for sentence in sentences if sentence]
        if not sentences:
            raise ValueError("Word2Vec needs at least one non-empty document")
        self.model = Word2Vec(
            sentences=sentences,
            vector_size=vector_size,
            window=window,
            min_count=1,
            sg=1,
            workers=workers,
            epochs=epochs,
            seed=seed,
        )
        self._capec_vectors = {
            capec_id: self._mean_vector(tokenize(split_camel_case(text)))
            for capec_id, text in capec_texts.items()
        }

    @property
    def capec_ids(self) -> tuple[str, ...]:
        return tuple(self._capec_ids)

    def _mean_vector(self, tokens: list[str]) -> np.ndarray | None:
        vectors = [self.model.wv[token] for token in tokens if token in self.model.wv]
        if not vectors:
            return None
        vector = np.mean(vectors, axis=0)
        norm = float(np.linalg.norm(vector))
        if norm == 0.0:
            return None
        return vector / norm

    def scores(self, query: str, candidate_ids: Iterable[str]) -> dict[str, float]:
        known = sorted(
            {capec_id for capec_id in candidate_ids if capec_id in self._capec_vectors},
            key=lambda capec_id: self._order[capec_id],
        )
        if not known:
            return {}
        query_vector = self._mean_vector(tokenize(split_camel_case(query)))
        if query_vector is None:
            return {capec_id: 0.0 for capec_id in known}
        scores: dict[str, float] = {}
        for capec_id in known:
            capec_vector = self._capec_vectors[capec_id]
            scores[capec_id] = (
                0.0 if capec_vector is None else float(np.dot(query_vector, capec_vector))
            )
        return scores

    def select(self, query: str, candidate_ids: Iterable[str]) -> tuple[str | None, float]:
        return best_candidate(self.scores(query, candidate_ids))
