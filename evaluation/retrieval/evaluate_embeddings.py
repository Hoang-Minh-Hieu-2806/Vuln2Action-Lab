"""Neural embedding retrieval remains a measured-gated future experiment.

Keyword, TF-IDF, and MITRE-enriched semantic retrieval run through
``evaluation/retrieval/evaluate_retrieval.py``. The semantic backend is lexical
plus knowledge-graph enrichment, not a neural encoder. Add an embedding
backend only if the current backends demonstrably underperform on cases that
semantic enrichment cannot cover.
"""

from __future__ import annotations


def main() -> None:
    raise SystemExit(
        "Embedding evaluation is intentionally not implemented. "
        "Run: python scripts/run_evaluation.py --stage retrieval"
    )


if __name__ == "__main__":
    main()
