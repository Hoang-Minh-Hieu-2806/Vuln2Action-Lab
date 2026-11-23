"""Semantic cache must preserve ranking exactly and invalidate by corpus identity."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from vuln2action.domain import KnowledgeDocument
from vuln2action.retrieval.corpus import load_seed_corpus
from vuln2action.retrieval.semantic import SemanticBackend, clear_semantic_cache, semantic_search


@pytest.fixture(autouse=True)
def clean_cache():
    clear_semantic_cache()
    yield
    clear_semantic_cache()


def _documents() -> list[KnowledgeDocument]:
    return load_seed_corpus()[:8]


def test_cached_search_matches_freshly_fitted_search():
    documents = _documents()
    query = documents[0].name

    clear_semantic_cache()
    fresh = semantic_search(query, documents, top_k=3)
    cached = semantic_search(query, documents, top_k=3)

    assert [(index, score) for index, score in fresh] == [(index, score) for index, score in cached]


def test_clear_cache_keeps_results_identical():
    documents = _documents()
    query = documents[1].name
    first = semantic_search(query, documents, top_k=3)
    clear_semantic_cache()
    assert semantic_search(query, documents, top_k=3) == first


def test_corpus_change_creates_a_new_cache_entry():
    documents = _documents()
    query = "database injection"
    original = semantic_search(query, documents, top_k=3)

    changed = [
        KnowledgeDocument(
            doc_id=document.doc_id,
            kind=document.kind,
            name=document.name,
            text=f"{document.text} database injection",
            source=document.source,
        )
        for document in documents
    ]
    updated = semantic_search(query, changed, top_k=3)

    assert updated != original
    assert semantic_search(query, changed, top_k=3) == updated


def test_different_backend_weights_do_not_share_scores():
    documents = _documents()
    query = documents[2].name
    backend = SemanticBackend(name_weight=2, char_weight=0.5)
    other = SemanticBackend(name_weight=2, char_weight=0.25)
    first = backend.search(query, documents, top_k=3)
    second = other.search(query, documents, top_k=3)

    assert [(c.source, c.score) for c in first] == [
        (c.source, c.score) for c in backend.search(query, documents, top_k=3)
    ]
    assert [(c.source, c.score) for c in second] == [
        (c.source, c.score) for c in other.search(query, documents, top_k=3)
    ]


def test_concurrent_searches_are_stable():
    documents = _documents()
    query = documents[3].name
    expected = semantic_search(query, documents, top_k=3)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(lambda _: semantic_search(query, documents, top_k=3), range(16))
        )
    assert all(result == expected for result in results)
