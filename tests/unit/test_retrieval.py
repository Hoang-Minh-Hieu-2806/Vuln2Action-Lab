"""Unit tests for retrieval baselines + ranker."""
from src.ingestion.cve import get_sample_cve
from src.retrieval.keyword import keyword_search
from src.retrieval.ranker import build_contexts_for_cve, rank_contexts, RetrievedContext
from src.retrieval.tfidf import tfidf_search


def test_keyword_search_orders():
    docs = ["xss search page", "sql login", "traversal files"]
    top = keyword_search("xss search", docs, top_k=1)
    assert top[0][0] == 0


def test_tfidf_search_runs():
    docs = ["xss search page", "sql login", "traversal files"]
    top = tfidf_search("sql login", docs, top_k=2)
    assert len(top) == 2


def test_ranker_dedupes_and_build_contexts():
    cve = get_sample_cve("CVE-2024-0001")
    ctxs = build_contexts_for_cve(cve, top_k=3)
    assert any(c.source == "CWE-79" for c in ctxs)
    dupes = [RetrievedContext("A", "t", 0.1), RetrievedContext("A", "t", 0.9)]
    assert rank_contexts(dupes, top_k=2)[0].score == 0.9
