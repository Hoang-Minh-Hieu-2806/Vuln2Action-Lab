"""Backend-agnostic retrieval evaluation with real metrics (no fabricated scores).

Precision/recall/F1 use the top-k cutoff; MRR uses the full ranking and
``mrr_at_k`` reports the cutoff variant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from evaluation.retrieval.metrics import f1_at_k, mrr, precision_at_k, recall_at_k
from vuln2action.domain import KnowledgeDocument
from vuln2action.retrieval import get_backend
from vuln2action.utils.filesystem import read_json


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    cve_id: str
    query: str
    relevant: list[str] = Field(min_length=1)


class Benchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0.0"
    description: str = ""
    labels_source: str = ""
    k: int = Field(default=3, ge=1)
    cases: list[BenchmarkCase] = Field(min_length=1)


def load_benchmark(path: str | Path) -> Benchmark:
    return Benchmark.model_validate(read_json(path))


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def evaluate_backend(
    backend_name: str,
    corpus: list[KnowledgeDocument],
    benchmark: Benchmark,
    k: int | None = None,
) -> dict[str, Any]:
    top_k = k or benchmark.k
    backend = get_backend(backend_name)
    corpus_ids = {document.doc_id for document in corpus}
    rows: list[dict[str, Any]] = []
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    rankings: list[list[str]] = []
    relevant_sets: list[set[str]] = []

    for case in benchmark.cases:
        full_hits = backend.search(case.query, corpus, top_k=len(corpus))
        full_ranking = [hit.source for hit in full_hits]
        retrieved = full_ranking[:top_k]
        relevant = set(case.relevant)
        precision = precision_at_k(retrieved, relevant, top_k)
        recall = recall_at_k(retrieved, relevant, top_k)
        f1 = f1_at_k(retrieved, relevant, top_k)
        hit_rank = next(
            (rank for rank, doc_id in enumerate(full_ranking, start=1) if doc_id in relevant),
            0,
        )
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)
        rankings.append(full_ranking)
        relevant_sets.append(relevant)
        rows.append(
            {
                "case_id": case.case_id,
                "cve_id": case.cve_id,
                "retrieved": retrieved,
                "relevant": case.relevant,
                "relevant_in_corpus": sorted(relevant & corpus_ids),
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "reciprocal_rank": (1.0 / hit_rank) if hit_rank else 0.0,
                "reciprocal_rank_at_k": (1.0 / hit_rank if hit_rank and hit_rank <= top_k else 0.0),
            }
        )

    fully_covered = sum(1 for case in benchmark.cases if set(case.relevant) <= corpus_ids)
    return {
        "backend": backend_name,
        "k": top_k,
        "precision": _mean(precisions),
        "recall": _mean(recalls),
        "f1": _mean(f1s),
        "mrr": mrr(rankings, relevant_sets),
        "mrr_at_k": _mean([row["reciprocal_rank_at_k"] for row in rows]),
        "cases_evaluated": len(benchmark.cases),
        "cases_fully_covered": fully_covered,
        "cases": rows,
    }


def evaluate(
    backends: list[str],
    corpus: list[KnowledgeDocument],
    benchmark: Benchmark,
    k: int | None = None,
) -> dict[str, Any]:
    top_k = k or benchmark.k
    results = {name: evaluate_backend(name, corpus, benchmark, k=top_k) for name in backends}
    return {
        "benchmark_version": benchmark.version,
        "labels_source": benchmark.labels_source,
        "k": top_k,
        "corpus_documents": len(corpus),
        "benchmark_cases": len(benchmark.cases),
        "results": results,
    }
