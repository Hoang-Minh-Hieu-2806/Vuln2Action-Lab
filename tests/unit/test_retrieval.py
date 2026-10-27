"""Unit tests for retrieval baselines + ranker."""

from vuln2action.connectors import get_sample_cve
from vuln2action.domain import RetrievedContext
from vuln2action.retrieval.keyword import keyword_search
from vuln2action.retrieval.ranker import build_contexts_for_cve, rank_contexts
from vuln2action.retrieval.text import split_camel_case
from vuln2action.retrieval.tfidf import tfidf_search


def test_keyword_search_orders():
    docs = ["xss search page", "sql login", "traversal files"]
    top = keyword_search("xss search", docs, top_k=1)
    assert top[0][0] == 0


def test_tfidf_search_runs():
    docs = ["xss search page", "sql login", "traversal files"]
    top = tfidf_search("sql login", docs, top_k=2)
    assert top
    assert top[0][0] == 1
    assert all(score > 0.0 for _, score in top)


def test_camel_case_split_preserves_normal_tokens():
    assert split_camel_case("ShellShock Log4j2 JNDI") == "Shell Shock Log4j2 JNDI"


def test_lexical_search_drops_zero_score_documents():
    docs = ["xss search page", "sql login", "traversal files"]
    assert keyword_search("the and of", docs, top_k=2) == []
    assert tfidf_search("zzzz", docs, top_k=2) == []


def test_ranker_dedupes_and_build_contexts():
    cve = get_sample_cve("CVE-2024-0001")
    ctxs = build_contexts_for_cve(cve, top_k=3)
    assert any(c.source == "CWE-79" for c in ctxs)
    dupes = [
        RetrievedContext(source="A", text="t", score=0.1),
        RetrievedContext(source="A", text="t", score=0.9),
    ]
    assert rank_contexts(dupes, top_k=2)[0].score == 0.9
