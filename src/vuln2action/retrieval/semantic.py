"""Knowledge-enriched semantic retrieval over MITRE CWE/CAPEC metadata.

The backend is deliberately local and deterministic. It does not call an
embedding API or download a model. Instead it closes vocabulary gaps by
indexing three pieces of MITRE metadata alongside each CWE definition:

* alternate terms from the CWE entry;
* names of related CAPEC attack patterns;
* definitions of direct parent weaknesses.

Word and character n-gram TF-IDF scores are then combined. The character
representation helps with morphology (``buffer``/``buffers``,
``ShellShock``/``shell``) while the word representation keeps the ranking
interpretable. Neural embeddings remain an explicit stub.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from xml.etree import ElementTree

from pydantic import BaseModel, ConfigDict, Field

from vuln2action.domain import KnowledgeDocument, RetrievedContext
from vuln2action.retrieval.base import RetrievalBackend
from vuln2action.retrieval.text import STOPWORDS, split_camel_case, tokenize
from vuln2action.utils.filesystem import read_json, repo_path

TRACKED_CONTEXT = ("data", "samples", "cwe_semantic_context.json")
RAW_CWE = ("data", "raw", "cwe", "cwec_latest.xml")
RAW_CAPEC = ("data", "raw", "capec", "capec_latest.xml")

_STOP_WORDS = sorted(STOPWORDS)


class RelatedAttackPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capec_id: str
    name: str = ""


class ParentWeakness(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwe_id: str
    name: str = ""
    description: str = ""


class SemanticContext(BaseModel):
    """MITRE metadata that is not part of the flat CWE description."""

    model_config = ConfigDict(extra="forbid")
    doc_id: str
    alternate_terms: list[str] = Field(default_factory=list)
    related_attack_patterns: list[RelatedAttackPattern] = Field(default_factory=list)
    parents: list[ParentWeakness] = Field(default_factory=list)


class SemanticContextFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0.0"
    source: str = ""
    documents: list[SemanticContext] = Field(default_factory=list)


def _read_xml(source: str | bytes | Path) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    text = str(source)
    if text.lstrip().startswith("<"):
        return text.encode("utf-8")
    return Path(text).read_bytes()


def _xml_root(source: str | bytes | Path) -> ElementTree.Element:
    root = ElementTree.fromstring(_read_xml(source))
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


def _clean(text: str | None) -> str:
    return " ".join((text or "").split())


def build_semantic_contexts(
    cwe_source: str | bytes | Path,
    capec_source: str | bytes | Path,
    doc_ids: set[str] | None = None,
) -> dict[str, SemanticContext]:
    """Extract searchable MITRE context for the requested CWE ids.

    ``doc_ids=None`` extracts every CWE in the catalog. Parents are looked up
    even when they are outside the requested set so their definitions can be
    attached to a child document.
    """
    capec_names: dict[str, str] = {}
    for attack in _xml_root(capec_source).iter("Attack_Pattern"):
        raw_id = (attack.get("ID") or "").strip()
        if raw_id:
            capec_names[f"CAPEC-{raw_id}"] = (attack.get("Name") or "").strip()

    weaknesses: dict[str, ElementTree.Element] = {}
    for weakness in _xml_root(cwe_source).iter("Weakness"):
        raw_id = (weakness.get("ID") or "").strip()
        if raw_id:
            weaknesses.setdefault(f"CWE-{raw_id}", weakness)

    contexts: dict[str, SemanticContext] = {}
    for cwe_id, weakness in weaknesses.items():
        if doc_ids is not None and cwe_id not in doc_ids:
            continue

        alternate_terms: list[str] = []
        for term in weakness.findall(".//Alternate_Term/Term"):
            cleaned = _clean(term.text)
            if cleaned and cleaned not in alternate_terms:
                alternate_terms.append(cleaned)

        # Index CAPEC names, not full descriptions: generic weaknesses such as
        # CWE-20 map to dozens of patterns, and full descriptions make them
        # dominate unrelated queries. Names add vocabulary without that hub effect.
        related: list[RelatedAttackPattern] = []
        seen_patterns: set[str] = set()
        for relation in weakness.findall(".//Related_Attack_Pattern"):
            raw_id = (relation.get("CAPEC_ID") or "").strip()
            if not raw_id:
                continue
            capec_id = f"CAPEC-{raw_id}"
            if capec_id in seen_patterns:
                continue
            seen_patterns.add(capec_id)
            related.append(
                RelatedAttackPattern(
                    capec_id=capec_id,
                    name=capec_names.get(capec_id, ""),
                )
            )

        parents: list[ParentWeakness] = []
        seen_parents: set[str] = set()
        for relation in weakness.findall(".//Related_Weakness"):
            if relation.get("Nature") != "ChildOf":
                continue
            raw_id = (relation.get("CWE_ID") or "").strip()
            if not raw_id:
                continue
            parent_id = f"CWE-{raw_id}"
            if parent_id in seen_parents:
                continue
            parent = weaknesses.get(parent_id)
            if parent is None:
                continue
            seen_parents.add(parent_id)
            parents.append(
                ParentWeakness(
                    cwe_id=parent_id,
                    name=(parent.get("Name") or "").strip(),
                    description=_clean(parent.findtext("Description")),
                )
            )

        contexts[cwe_id] = SemanticContext(
            doc_id=cwe_id,
            alternate_terms=alternate_terms,
            related_attack_patterns=related,
            parents=parents,
        )
    return contexts


def load_semantic_contexts(path: str | Path) -> dict[str, SemanticContext]:
    raw = read_json(path)
    if not isinstance(raw, dict):
        raise TypeError(f"Semantic context file must be a JSON object: {path}")
    parsed = SemanticContextFile.model_validate(raw)
    return {context.doc_id: context for context in parsed.documents}


class SemanticEnricher:
    """Append MITRE graph context to a CWE document before indexing."""

    def __init__(self, contexts: Mapping[str, SemanticContext] | None = None) -> None:
        self.contexts = dict(contexts or {})

    def enrich(self, document: KnowledgeDocument) -> str:
        context = self.contexts.get(document.doc_id)
        if context is None:
            return document.text
        parts = [document.text]
        if context.alternate_terms:
            parts.append("Alternate terms: " + "; ".join(context.alternate_terms))
        if context.related_attack_patterns:
            patterns = " ".join(
                f"{pattern.capec_id} {pattern.name}".strip()
                for pattern in context.related_attack_patterns
            )
            parts.append("Related attack patterns: " + patterns)
        for parent in context.parents:
            parts.append(
                f"Parent weakness {parent.cwe_id} {parent.name}: {parent.description}".strip()
            )
        return " ".join(part for part in parts if part)


def _index_text(
    document: KnowledgeDocument,
    enricher: SemanticEnricher,
    name_weight: int,
) -> str:
    enriched = enricher.enrich(document)
    name = document.name.strip()
    if not name:
        return enriched
    return " ".join([name] * name_weight + [enriched])


@lru_cache(maxsize=1)
def default_semantic_enricher() -> SemanticEnricher:
    """Load the tracked seed context and, when available, the full catalogs.

    The tracked file keeps CI and offline seed-corpus runs reproducible. Raw
    CWE/CAPEC snapshots are optional and only read from disk; no network access
    happens here.
    """
    contexts: dict[str, SemanticContext] = {}
    tracked = repo_path(*TRACKED_CONTEXT)
    if tracked.is_file():
        contexts.update(load_semantic_contexts(tracked))

    cwe_path = repo_path(*RAW_CWE)
    capec_path = repo_path(*RAW_CAPEC)
    if cwe_path.is_file() and capec_path.is_file():
        try:
            contexts.update(build_semantic_contexts(cwe_path, capec_path))
        except (OSError, ValueError, ElementTree.ParseError):
            # A malformed/partial snapshot must not break offline retrieval.
            pass
    return SemanticEnricher(contexts)


def semantic_search(
    query: str,
    documents: list[KnowledgeDocument],
    top_k: int = 3,
    enricher: SemanticEnricher | None = None,
    name_weight: int = 2,
    char_weight: float = 0.5,
) -> list[tuple[int, float]]:
    """Rank enriched documents with a word/character TF-IDF blend."""
    if not documents or top_k <= 0:
        return []
    if not 0.0 <= char_weight <= 1.0:
        raise ValueError("char_weight must be between 0 and 1")
    if name_weight < 1:
        raise ValueError("name_weight must be at least 1")
    query_text = split_camel_case(query)
    if not tokenize(query_text):
        return []

    active_enricher = enricher or default_semantic_enricher()
    texts = [
        split_camel_case(_index_text(document, active_enricher, name_weight))
        for document in documents
    ]

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        from vuln2action.retrieval.keyword import keyword_search

        return keyword_search(split_camel_case(query), texts, top_k=top_k)

    word_vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words=_STOP_WORDS,
        token_pattern=r"(?u)\b\w+\b",
    )
    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        sublinear_tf=True,
    )
    word_matrix = word_vectorizer.fit_transform(texts)
    char_matrix = char_vectorizer.fit_transform(texts)
    word_scores = cosine_similarity(word_vectorizer.transform([query_text]), word_matrix)[0]
    char_scores = cosine_similarity(char_vectorizer.transform([query_text]), char_matrix)[0]

    word_max = float(word_scores.max()) if word_scores.size else 0.0
    char_max = float(char_scores.max()) if char_scores.size else 0.0
    if word_max <= 0.0 and char_max <= 0.0:
        return []

    scored: list[tuple[int, float]] = []
    for index in range(len(documents)):
        score = 0.0
        if word_max > 0.0:
            score += (1.0 - char_weight) * (float(word_scores[index]) / word_max)
        if char_max > 0.0:
            score += char_weight * (float(char_scores[index]) / char_max)
        if score > 0.0:
            scored.append((index, score))
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[:top_k]


class SemanticBackend(RetrievalBackend):
    """MITRE-enriched lexical semantics behind the normal backend interface."""

    name = "semantic"

    def __init__(
        self,
        enricher: SemanticEnricher | None = None,
        name_weight: int = 2,
        char_weight: float = 0.5,
    ) -> None:
        if name_weight < 1:
            raise ValueError("name_weight must be at least 1")
        if not 0.0 <= char_weight <= 1.0:
            raise ValueError("char_weight must be between 0 and 1")
        self.enricher = enricher
        self.name_weight = name_weight
        self.char_weight = char_weight

    def search(
        self,
        query: str,
        documents: list[KnowledgeDocument],
        top_k: int = 3,
    ) -> list[RetrievedContext]:
        hits = semantic_search(
            query,
            documents,
            top_k=top_k,
            enricher=self.enricher,
            name_weight=self.name_weight,
            char_weight=self.char_weight,
        )
        return [
            RetrievedContext(
                source=documents[index].doc_id,
                text=documents[index].text,
                score=score,
                backend=self.name,
            )
            for index, score in hits
        ]
