"""Retrieval backends, corpus loading, and context ranking."""

from vuln2action.retrieval.base import RetrievalBackend, get_backend
from vuln2action.retrieval.corpus import (
    build_corpus,
    clear_corpus_cache,
    default_corpus,
    load_corpus_file,
    load_processed_corpus,
    load_seed_corpus,
)
from vuln2action.retrieval.keyword import KeywordBackend, keyword_score, keyword_search
from vuln2action.retrieval.ranker import build_contexts_for_cve, rank_contexts
from vuln2action.retrieval.semantic import (
    SemanticBackend,
    SemanticContext,
    SemanticEnricher,
    build_semantic_contexts,
    default_semantic_enricher,
    load_semantic_contexts,
    semantic_search,
)
from vuln2action.retrieval.text import STOPWORDS, document_text, split_camel_case, tokenize
from vuln2action.retrieval.tfidf import TfidfBackend, tfidf_search

__all__ = [
    "STOPWORDS",
    "KeywordBackend",
    "RetrievalBackend",
    "SemanticBackend",
    "SemanticContext",
    "SemanticEnricher",
    "TfidfBackend",
    "build_contexts_for_cve",
    "build_corpus",
    "build_semantic_contexts",
    "clear_corpus_cache",
    "default_corpus",
    "default_semantic_enricher",
    "document_text",
    "get_backend",
    "keyword_score",
    "keyword_search",
    "load_corpus_file",
    "load_processed_corpus",
    "load_seed_corpus",
    "load_semantic_contexts",
    "rank_contexts",
    "semantic_search",
    "split_camel_case",
    "tfidf_search",
    "tokenize",
]
