"""CWE -> CAPEC candidate retrieval and semantic ranking (Algorithm 1 analogue).

The reference pipeline maps a CVE to CAPEC in two stages:

1. **Candidate expansion** through the MITRE taxonomy. NVD assigns CWEs to a
   CVE and every CAPEC references one or more ``Related_Weakness`` entries, so
   ``CVE --CWE--> candidates`` is exact and needs no model.
2. **Ranking** those candidates against the CVE description. The paper compares
   TF-IDF and Word2Vec with cosine similarity and keeps the best match.

This module implements both stages behind a small, dependency-light interface.
Word2Vec needs ``gensim``; it is an *optional* dependency, so the module imports
it lazily and raises :class:`MissingDependencyError` with an actionable message
instead of failing at import time. TF-IDF reuses scikit-learn, which the project
already depends on, and falls back to the keyword baseline exactly like
:mod:`vuln2action.retrieval.tfidf`.

Everything here is deterministic: ties are broken by CAPEC id so two runs on the
same inputs always produce the same ranking.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from xml.etree import ElementTree

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vuln2action.retrieval.text import STOPWORDS, split_camel_case, tokenize
from vuln2action.utils.filesystem import repo_path

RAW_CAPEC = ("data", "raw", "capec", "capec_latest.xml")

_STOP_WORDS = sorted(STOPWORDS)
_CAPEC_ID = re.compile(r"^CAPEC-\d+$")
_CWE_ID = re.compile(r"^CWE-\d+$")

DEFAULT_METHODS = ("tfidf", "word2vec")


WORD2VEC_EXTRA = 'pip install -e ".[ranking]"'


class MissingDependencyError(RuntimeError):
    """Raised when an optional ranking backend is not installed."""


class CapecDocument(BaseModel):
    """One CAPEC attack pattern plus the CWEs it is declared to relate to."""

    model_config = ConfigDict(extra="forbid")
    capec_id: str
    name: str = ""
    description: str = ""
    cwe_ids: list[str] = Field(default_factory=list)

    @field_validator("capec_id")
    @classmethod
    def must_be_capec_id(cls, value: str) -> str:
        value = value.strip().upper()
        if not _CAPEC_ID.match(value):
            raise ValueError(f"not a CAPEC id: {value!r}")
        return value

    def searchable_text(self) -> str:
        name = self.name.strip()
        body = f"{self.capec_id} {name}: {self.description}".strip()
        return body

    def boosted_text(self, name_weight: int = 2) -> str:
        """Repeat the pattern name ahead of the body as a cheap field boost."""
        if name_weight < 1:
            raise ValueError("name_weight must be at least 1")
        name = self.name.strip()
        text = self.searchable_text()
        if not name:
            return text
        return " ".join([name] * name_weight + [text])


class CapecMapping(BaseModel):
    """A ranked CAPEC choice for one CVE under one ranking method."""

    model_config = ConfigDict(extra="forbid")
    cve_id: str
    method: str
    capec_id: str
    score: float
    candidates: list[str] = Field(default_factory=list)
    ranked: list[tuple[str, float]] = Field(default_factory=list)

    @property
    def runner_up(self) -> str | None:
        return self.ranked[1][0] if len(self.ranked) > 1 else None

    @property
    def margin(self) -> float:
        """Score gap between the winner and the runner-up (0.0 if only one)."""
        return self.score - self.ranked[1][1] if len(self.ranked) > 1 else 0.0


@dataclass(frozen=True)
class CapecIndex:
    """Immutable CAPEC corpus with the CWE -> CAPEC reverse index."""

    documents: Mapping[str, CapecDocument]
    cwe_index: Mapping[str, tuple[str, ...]]
    source: str = ""
    _ordered_ids: tuple[str, ...] = field(default=(), repr=False)

    @property
    def capec_ids(self) -> tuple[str, ...]:
        return self._ordered_ids or tuple(sorted(self.documents))

    def candidates_for_cwes(self, cwe_ids: Iterable[str]) -> list[str]:
        """Union of CAPEC ids related to any of ``cwe_ids``, sorted for stability.

        Unknown, blank, or malformed CWE ids are ignored rather than raising: a
        CVE with partially unmapped weaknesses still yields whatever candidates
        the mapped ones provide.
        """
        found: set[str] = set()
        for raw in cwe_ids:
            key = (raw or "").strip().upper()
            if not _CWE_ID.match(key):
                continue
            found.update(self.cwe_index.get(key, ()))
        return sorted(found)

    def text_for(self, capec_id: str, name_weight: int = 2) -> str:
        return self.documents[capec_id].boosted_text(name_weight=name_weight)


def _read_xml(source: str | bytes | Path) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    text = str(source)
    if text.lstrip().startswith("<"):
        return text.encode("utf-8")
    return Path(text).read_bytes()


def _clean(text: str | None) -> str:
    return " ".join((text or "").split())


def parse_capec_related_weaknesses(source: str | bytes | Path) -> list[CapecDocument]:
    """Parse a CAPEC catalog into patterns with their related CWE ids.

    Namespaces are stripped like the other MITRE parsers in this project. A
    pattern that declares no ``Related_Weakness`` is still returned (with an
    empty ``cwe_ids`` list) so the corpus stays complete for ranking; it just
    never becomes a candidate. ``Execution_Flow`` steps are intentionally not
    parsed here: this module ranks *which* pattern applies, not its steps.
    """
    root = ElementTree.fromstring(_read_xml(source))
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]

    documents: list[CapecDocument] = []
    seen: set[str] = set()
    for attack in root.iter("Attack_Pattern"):
        raw_id = (attack.get("ID") or "").strip()
        if not raw_id:
            continue
        capec_id = f"CAPEC-{raw_id}".upper()
        if not _CAPEC_ID.match(capec_id) or capec_id in seen:
            continue
        seen.add(capec_id)
        cwe_ids: list[str] = []
        for relation in attack.findall(".//Related_Weakness"):
            raw_cwe = (relation.get("CWE_ID") or "").strip()
            if not raw_cwe:
                continue
            cwe_id = f"CWE-{raw_cwe}".upper()
            if _CWE_ID.match(cwe_id) and cwe_id not in cwe_ids:
                cwe_ids.append(cwe_id)
        documents.append(
            CapecDocument(
                capec_id=capec_id,
                name=_clean(attack.get("Name")),
                description=_clean(attack.findtext("Description")),
                cwe_ids=cwe_ids,
            )
        )
    return documents


def build_capec_index(
    documents: Iterable[CapecDocument],
    source: str = "",
) -> CapecIndex:
    """Build the immutable corpus + reverse index from parsed documents."""
    by_id: dict[str, CapecDocument] = {}
    reverse: dict[str, list[str]] = {}
    for document in documents:
        if document.capec_id in by_id:
            continue
        by_id[document.capec_id] = document
        for cwe_id in document.cwe_ids:
            reverse.setdefault(cwe_id, []).append(document.capec_id)
    frozen_reverse = {cwe: tuple(sorted(ids)) for cwe, ids in reverse.items()}
    return CapecIndex(
        documents=by_id,
        cwe_index=frozen_reverse,
        source=source,
        _ordered_ids=tuple(sorted(by_id)),
    )


def load_capec_index(path: str | Path | None = None) -> CapecIndex:
    """Parse a CAPEC XML snapshot from disk (no download, ever)."""
    snapshot = Path(path) if path is not None else repo_path(*RAW_CAPEC)
    if not snapshot.is_file():
        raise FileNotFoundError(
            f"CAPEC catalog not found: {snapshot}. "
            "Run: python scripts/download_data.py --source capec"
        )
    return build_capec_index(parse_capec_related_weaknesses(snapshot), source=str(snapshot))


@lru_cache(maxsize=1)
def default_capec_index() -> CapecIndex:
    return load_capec_index()


def clear_capec_cache() -> None:
    default_capec_index.cache_clear()


def _query_text(description: str) -> str:
    return split_camel_case(description or "")


def _rank(scored: Iterable[tuple[str, float]]) -> list[tuple[str, float]]:
    """Sort by descending score, breaking ties by CAPEC id (deterministic)."""
    ranked = [(capec_id, float(score)) for capec_id, score in scored if float(score) > 0.0]
    ranked.sort(key=lambda item: (-item[1], item[0]))
    return ranked


def tfidf_cosine_scores(
    query: str,
    index: CapecIndex,
    candidate_ids: Sequence[str],
    name_weight: int = 2,
) -> list[tuple[str, float]]:
    """Cosine similarity between TF-IDF vectors of query and candidates."""
    if not candidate_ids:
        return []
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:  # pragma: no cover - sklearn is a declared dependency
        from vuln2action.retrieval.keyword import keyword_score

        return [
            (cid, keyword_score(query, index.text_for(cid, name_weight))) for cid in candidate_ids
        ]

    texts = [index.text_for(cid, name_weight) for cid in candidate_ids]
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words=_STOP_WORDS,
        token_pattern=r"(?u)\b\w+\b",
    )
    document_matrix = vectorizer.fit_transform(texts)
    query_vector = vectorizer.transform([query])
    similarities = cosine_similarity(query_vector, document_matrix)[0]
    return [(cid, float(score)) for cid, score in zip(candidate_ids, similarities)]


def _require_gensim():
    try:
        import gensim  # noqa: F401  (imported for the availability check only)
    except ImportError as exc:  # pragma: no cover - exercised only without gensim
        raise MissingDependencyError(
            "Word2Vec ranking needs the optional 'gensim' package. "
            f"Install it with: {WORD2VEC_EXTRA}"
        ) from exc


def train_word2vec(
    index: CapecIndex,
    vector_size: int = 100,
    window: int = 5,
    min_count: int = 1,
    epochs: int = 40,
    seed: int = 42,
    sg: int = 1,
):
    """Train a small skip-gram Word2Vec model on the CAPEC corpus sentences.

    Each candidate document is one sentence. Training on the same corpus both
    methods rank against keeps the comparison fair and fully offline.
    """
    _require_gensim()
    from gensim.models import Word2Vec

    sentences = [
        tokenize(split_camel_case(index.text_for(capec_id, name_weight=1)))
        for capec_id in index.capec_ids
    ]
    sentences = [sentence for sentence in sentences if sentence]
    if not sentences:
        raise ValueError("CAPEC corpus produced no tokens to train Word2Vec on")
    return Word2Vec(
        sentences,
        vector_size=vector_size,
        window=window,
        min_count=min_count,
        workers=1,
        seed=seed,
        epochs=epochs,
        sg=sg,
    )


def _mean_vector(model, text: str):
    import numpy as np

    tokens = [token for token in tokenize(split_camel_case(text)) if token in model.wv]
    if not tokens:
        return None
    vector = np.mean([model.wv[token] for token in tokens], axis=0)
    norm = float(np.linalg.norm(vector))
    return vector / norm if norm else None


def word2vec_cosine_scores(
    query: str,
    index: CapecIndex,
    candidate_ids: Sequence[str],
    model=None,
    name_weight: int = 2,
) -> list[tuple[str, float]]:
    """Cosine similarity between mean Word2Vec vectors of query and candidates.

    Words outside the trained vocabulary are skipped. A query with no known
    word yields all-zero scores, in which case the caller falls back to the
    deterministic id order (never a silent random pick).
    """
    if not candidate_ids:
        return []
    active_model = model if model is not None else train_word2vec(index)
    query_vector = _mean_vector(active_model, query)
    if query_vector is None:
        return [(cid, 0.0) for cid in candidate_ids]
    scored: list[tuple[str, float]] = []
    for capec_id in candidate_ids:
        document_vector = _mean_vector(active_model, index.text_for(capec_id, name_weight))
        if document_vector is None:
            scored.append((capec_id, 0.0))
            continue
        scored.append((capec_id, float(query_vector @ document_vector)))
    return scored


def rank_candidates(
    description: str,
    cwe_ids: Iterable[str],
    method: str = "tfidf",
    index: CapecIndex | None = None,
    word2vec_model=None,
    name_weight: int = 2,
) -> list[tuple[str, float]]:
    """Return ``[(capec_id, score), ...]`` ranked for one vulnerability."""
    active_index = index if index is not None else default_capec_index()
    candidates = active_index.candidates_for_cwes(cwe_ids)
    if not candidates:
        return []
    query = _query_text(description)
    if not tokenize(query):
        return []
    key = (method or "").strip().lower()
    if key in {"tfidf", "tf-idf"}:
        scored = tfidf_cosine_scores(query, active_index, candidates, name_weight=name_weight)
    elif key in {"word2vec", "w2v"}:
        scored = word2vec_cosine_scores(
            query,
            active_index,
            candidates,
            model=word2vec_model,
            name_weight=name_weight,
        )
    else:
        raise ValueError(f"Unknown CAPEC ranking method: {method!r}")
    return _rank(scored)


def map_cve_to_capec(
    cve_id: str,
    description: str,
    cwe_ids: Iterable[str],
    method: str = "tfidf",
    index: CapecIndex | None = None,
    word2vec_model=None,
    name_weight: int = 2,
) -> CapecMapping | None:
    """Map one CVE to its best CAPEC; ``None`` when no candidate exists."""
    active_index = index if index is not None else default_capec_index()
    cwe_list = list(cwe_ids)
    candidates = active_index.candidates_for_cwes(cwe_list)
    ranked = rank_candidates(
        description,
        cwe_list,
        method=method,
        index=active_index,
        word2vec_model=word2vec_model,
        name_weight=name_weight,
    )
    if not ranked:
        return None
    best_id, best_score = ranked[0]
    return CapecMapping(
        cve_id=cve_id,
        method=(method or "").strip().lower(),
        capec_id=best_id,
        score=best_score,
        candidates=candidates,
        ranked=ranked,
    )
