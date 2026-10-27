"""Evaluate TF-IDF retrieval on the placeholder benchmark (Phase 3/7).

TODO: extend benchmark.json with relevance judgements, then report P/R/F1/MRR.
"""
from __future__ import annotations

from vuln2action.retrieval.tfidf import tfidf_search  # noqa: E402


def main() -> None:
    docs = ["XSS search endpoint", "SQL login bypass", "path traversal download"]
    print(tfidf_search("xss search", docs, top_k=2))


if __name__ == "__main__":
    main()
