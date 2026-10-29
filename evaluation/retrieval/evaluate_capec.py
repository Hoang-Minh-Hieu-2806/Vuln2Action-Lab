"""CVE -> CAPEC evaluation: TF-IDF vs Word2Vec on identical candidates.

Two protocols are reported side by side, because the choice matters:

``membership``
    The paper's protocol (ref. [55] ground truth, 89/100 accuracy): a prediction
    counts as correct when the chosen CAPEC appears anywhere in the CVE's label
    set. Measured on this data the label set is exactly the CWE->CAPEC expansion,
    so this number is near the floor of "did candidate expansion work" and barely
    reflects ranking quality. It is reported for comparability, never as an
    achievement claim.

``discriminative``
    Metrics that actually depend on the ranking: how often the *top* pick is a
    CAPEC that none of the CVE's other candidates beats on lexical evidence, plus
    NDCG against graded relevance derived from the NVD CWE list. These expose the
    real TF-IDF vs Word2Vec difference.

Nothing is hard-coded: every number is computed from the benchmark file and the
CAPEC catalog. Cases where metrics are undefined are counted and reported instead
of being silently dropped or padded.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ROOT = Path(__file__).resolve().parents[2]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.retrieval.capec import (
    DEFAULT_METHODS,
    CapecIndex,
    MissingDependencyError,
    map_cve_to_capec,
    train_word2vec,
)
from vuln2action.utils.filesystem import ensure_dir, read_json, write_json

DEFAULT_BENCHMARK = "evaluation/datasets/capec_benchmark.json"
_CAPEC_PREFIX = "CAPEC-"


class CapecBenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    cve_id: str
    query: str
    cwe_ids: list[str] = Field(default_factory=list)
    capec_label: list[str] = Field(min_length=1)
    candidates: list[str] = Field(default_factory=list)
    label_source_cwe: list[str] = Field(default_factory=list)
    nvd_cwe_matches_label_source: bool = False

    @field_validator("candidates", "capec_label", "cwe_ids", "label_source_cwe")
    @classmethod
    def drop_duplicate_ids(cls, values: list[str]) -> list[str]:
        seen: list[str] = []
        for value in values:
            text = str(value).strip().upper()
            if text and text not in seen:
                seen.append(text)
        return seen


class CapecBenchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0.0"
    description: str = ""
    labels_source: str = ""
    query_source: str = ""
    candidate_source: str = ""
    label_semantics: str = ""
    built_at: str = ""
    seed: int | None = None
    requested_size: int | None = None
    sample_stats: dict[str, Any] = Field(default_factory=dict)
    k: int = Field(default=1, ge=1)
    cases: list[CapecBenchmarkCase] = Field(min_length=1)
    notes: str = ""


def load_capec_benchmark(path: str | Path) -> CapecBenchmark:
    return CapecBenchmark.model_validate(read_json(path))


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _hit_rank(ranked: Sequence[str], relevant: set[str]) -> int:
    for position, capec_id in enumerate(ranked, start=1):
        if capec_id in relevant:
            return position
    return 0


def _graded_relevance(case: CapecBenchmarkCase, index: CapecIndex) -> dict[str, float]:
    """Relevance of each candidate = share of the CVE's CWEs it is related to.

    This uses only the NVD CWE list and the CAPEC taxonomy, never the Galeax
    label, so it is independent of the label used by the membership protocol.
    """
    cwes = {cwe.strip().upper() for cwe in case.cwe_ids if cwe.strip()}
    if not cwes:
        return {}
    graded: dict[str, float] = {}
    for capec_id in case.candidates:
        document = index.documents.get(capec_id)
        if document is None:
            continue
        covered = len(set(document.cwe_ids) & cwes)
        graded[capec_id] = covered / len(cwes)
    return graded


def _ndcg(ranked: Sequence[str], graded: dict[str, float]) -> float | None:
    """NDCG over the full candidate ranking with exponential gain."""
    if not graded or len(set(graded.values())) < 2:
        return None
    dcg = sum(
        (2 ** graded.get(capec_id, 0.0) - 1) / math.log2(position + 1)
        for position, capec_id in enumerate(ranked, start=1)
    )
    ideal = sorted(graded.values(), reverse=True)
    idcg = sum(
        (2**gain - 1) / math.log2(position + 1) for position, gain in enumerate(ideal, start=1)
    )
    return dcg / idcg if idcg else None


def evaluate_method(
    method: str,
    benchmark: CapecBenchmark,
    index: CapecIndex,
    word2vec_model=None,
) -> list[dict[str, Any]]:
    """Rank every case with one method and return one numeric row per case.

    Rates are computed later by :func:`summarise_rows` so the same rows can be
    re-aggregated over a common subset of cases. That matters because TF-IDF can
    return an empty ranking when a description shares no token with any candidate,
    while Word2Vec still emits a (weak) score; comparing raw per-method totals
    would then reward the method that answers more often rather than the one that
    ranks better.
    """
    rows: list[dict[str, Any]] = []
    for case in benchmark.cases:
        relevant = set(case.capec_label)
        mapping = map_cve_to_capec(
            case.cve_id,
            case.query,
            case.cwe_ids,
            method=method,
            index=index,
            word2vec_model=word2vec_model,
        )
        base = {
            "case_id": case.case_id,
            "cve_id": case.cve_id,
            "candidates": len(case.candidates),
            "labels": len(relevant),
        }
        if mapping is None:
            rows.append(
                {
                    **base,
                    "predicted": "",
                    "score": 0.0,
                    "runner_up": "",
                    "margin": 0.0,
                    "hit_rank": 0,
                    "reciprocal_rank": 0.0,
                    "membership_correct": 0.0,
                    "recall_at_5": 0.0,
                    "graded_top1": 0.0,
                    "top1_is_best": 0.0,
                    "ndcg": None,
                    "ranked": False,
                }
            )
            continue

        ranked = [capec_id for capec_id, _ in mapping.ranked]
        rank = _hit_rank(ranked, relevant)
        graded = _graded_relevance(case, index)
        best_graded = max(graded.values()) if graded else 0.0
        achieved = graded.get(mapping.capec_id, 0.0)
        rows.append(
            {
                **base,
                "predicted": mapping.capec_id,
                "score": round(mapping.score, 6),
                "runner_up": mapping.runner_up or "",
                "margin": round(mapping.margin, 6),
                "hit_rank": rank,
                "reciprocal_rank": 1.0 / rank if rank else 0.0,
                "membership_correct": 1.0 if mapping.capec_id in relevant else 0.0,
                "recall_at_5": 1.0 if relevant & set(ranked[:5]) else 0.0,
                "graded_top1": achieved,
                "top1_is_best": 1.0 if best_graded > 0 and achieved >= best_graded else 0.0,
                "ndcg": _ndcg(ranked, graded),
                "ranked": True,
            }
        )
    return rows


def summarise_rows(
    rows: Sequence[dict[str, Any]], case_ids: set[str] | None = None
) -> dict[str, Any]:
    """Aggregate per-case rows, optionally restricted to a subset of case ids."""
    selected = [row for row in rows if case_ids is None or row["case_id"] in case_ids]
    total = len(selected)
    if not total:
        return {
            "cases": 0,
            "empty_rankings": 0,
            "membership": {"protocol": "", "top_1_accuracy": 0.0, "correct": 0},
            "discriminative": {
                "protocol": "",
                "evaluated_cases": 0,
                "top_1_cwe_coverage": 0.0,
                "top_1_matches_best_candidate": 0.0,
                "ndcg": 0.0,
                "recall_at_5": 0.0,
                "mrr": 0.0,
            },
        }
    ndcgs = [row["ndcg"] for row in selected if row["ndcg"] is not None]
    graded_top1 = [row["graded_top1"] for row in selected if row["ranked"]]
    return {
        "cases": total,
        "empty_rankings": sum(1 for row in selected if not row["ranked"]),
        "membership": {
            "protocol": "prediction in Galeax label set (paper-compatible)",
            "top_1_accuracy": _mean([row["membership_correct"] for row in selected]),
            "correct": int(sum(row["membership_correct"] for row in selected)),
        },
        "discriminative": {
            "protocol": "ranking quality against NVD-CWE graded relevance",
            "evaluated_cases": len(ndcgs),
            "top_1_cwe_coverage": _mean(graded_top1),
            "top_1_matches_best_candidate": _mean(
                [row["top1_is_best"] for row in selected if row["ranked"]]
            ),
            "ndcg": _mean(ndcgs),
            "recall_at_5": _mean([row["recall_at_5"] for row in selected]),
            "mrr": _mean([row["reciprocal_rank"] for row in selected]),
        },
    }


def evaluate(
    methods: Sequence[str],
    benchmark: CapecBenchmark,
    index: CapecIndex,
    word2vec_model=None,
) -> dict[str, Any]:
    """Evaluate every method, then aggregate on all cases and on a common subset."""
    all_rows = {
        method: evaluate_method(method, benchmark, index, word2vec_model=word2vec_model)
        for method in methods
    }
    # A fair head-to-head needs the cases that every method actually ranked.
    ranked_sets = [{row["case_id"] for row in rows if row["ranked"]} for rows in all_rows.values()]
    common = set.intersection(*ranked_sets) if ranked_sets else set()

    results: dict[str, Any] = {}
    for method, rows in all_rows.items():
        results[method] = {
            "method": method,
            **summarise_rows(rows),
            "common_subset": summarise_rows(rows, common),
            "rows": rows,
        }
    return {
        "benchmark_version": benchmark.version,
        "labels_source": benchmark.labels_source,
        "query_source": benchmark.query_source,
        "candidate_source": benchmark.candidate_source,
        "label_semantics": benchmark.label_semantics,
        "benchmark_cases": len(benchmark.cases),
        "common_subset_size": len(common),
        "capec_catalog": len(index.documents),
        "generated_at": datetime.now(UTC).isoformat(),
        "results": results,
    }


def _comparison_table(report: dict[str, Any]) -> str:
    header = (
        f"{'method':<10} {'top1(label)':>12} {'top1(cwe)':>10} {'best-cand':>10} "
        f"{'NDCG':>7} {'R@5':>7} {'MRR':>7} {'empty':>6}"
    )
    lines = [
        (
            f"cases: {report['benchmark_cases']} | CAPEC catalog: {report['capec_catalog']} | "
            f"common subset: {report['common_subset_size']}"
        ),
        "",
        "ALL CASES",
        header,
    ]
    for name, result in report["results"].items():
        membership = result["membership"]
        disc = result["discriminative"]
        lines.append(
            f"{name:<10} {membership['top_1_accuracy']:>12.4f} {disc['top_1_cwe_coverage']:>10.4f} "
            f"{disc['top_1_matches_best_candidate']:>10.4f} {disc['ndcg']:>7.4f} "
            f"{disc['recall_at_5']:>7.4f} {disc['mrr']:>7.4f} {result['empty_rankings']:>6}"
        )
    lines.extend(
        ["", f"COMMON SUBSET (cases every method ranked: {report['common_subset_size']})", header]
    )
    for name, result in report["results"].items():
        common = result["common_subset"]
        membership = common["membership"]
        disc = common["discriminative"]
        lines.append(
            f"{name:<10} {membership['top_1_accuracy']:>12.4f} {disc['top_1_cwe_coverage']:>10.4f} "
            f"{disc['top_1_matches_best_candidate']:>10.4f} {disc['ndcg']:>7.4f} "
            f"{disc['recall_at_5']:>7.4f} {disc['mrr']:>7.4f} {common['empty_rankings']:>6}"
        )
    return "\n".join(lines)


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# CVE -> CAPEC evaluation",
        "",
        f"- Cases: {report['benchmark_cases']}",
        f"- Common subset ranked by every method: {report['common_subset_size']}",
        f"- CAPEC catalog: {report['capec_catalog']} patterns",
        f"- Queries: {report['query_source']}",
        f"- Labels: {report['labels_source']}",
        "",
        (
            "`top1(label)` is the paper-compatible membership protocol. `top1(cwe)`, "
            "`best-cand` and `NDCG` are discriminative metrics computed against "
            "NVD-CWE graded relevance, independent of the Galeax label."
        ),
        "",
        "## All cases",
        "",
        "| Method | Top-1 (label) | Top-1 (CWE coverage) | Top-1 matches best | NDCG | R@5 | MRR | Empty |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, result in report["results"].items():
        membership = result["membership"]
        disc = result["discriminative"]
        lines.append(
            f"| {name} | {membership['top_1_accuracy']:.4f} | {disc['top_1_cwe_coverage']:.4f} | "
            f"{disc['top_1_matches_best_candidate']:.4f} | {disc['ndcg']:.4f} | "
            f"{disc['recall_at_5']:.4f} | {disc['mrr']:.4f} | {result['empty_rankings']} |"
        )
    lines.extend(
        [
            "",
            f"## Common subset ({report['common_subset_size']} cases)",
            "",
            "| Method | Top-1 (label) | Top-1 (CWE coverage) | Top-1 matches best | NDCG | R@5 | MRR |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for name, result in report["results"].items():
        common = result["common_subset"]
        membership = common["membership"]
        disc = common["discriminative"]
        lines.append(
            f"| {name} | {membership['top_1_accuracy']:.4f} | {disc['top_1_cwe_coverage']:.4f} | "
            f"{disc['top_1_matches_best_candidate']:.4f} | {disc['ndcg']:.4f} | "
            f"{disc['recall_at_5']:.4f} | {disc['mrr']:.4f} |"
        )
    return "\n".join(lines) + "\n"


def _write_csv(path: Path, report: dict[str, Any]) -> Path:
    fieldnames = [
        "method",
        "case_id",
        "cve_id",
        "predicted",
        "score",
        "runner_up",
        "margin",
        "candidates",
        "labels",
        "hit_rank",
        "reciprocal_rank",
        "membership_correct",
        "graded_top1",
        "ndcg",
    ]
    row_fields = [name for name in fieldnames if name != "method"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for method, result in report["results"].items():
            for row in result["rows"]:
                writer.writerow({"method": method, **{key: row.get(key, "") for key in row_fields}})
    return path


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _safe_stdout() -> None:
    """Keep Windows cp1252 consoles from crashing on non-ASCII repo paths."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(description="Evaluate CVE -> CAPEC mapping methods.")
    parser.add_argument(
        "--benchmark",
        default=DEFAULT_BENCHMARK,
        help=f"Benchmark JSON (default: {DEFAULT_BENCHMARK}).",
    )
    parser.add_argument(
        "--capec",
        default="",
        help="CAPEC XML snapshot (default: data/raw/capec/capec_latest.xml).",
    )
    parser.add_argument(
        "--methods",
        default=",".join(DEFAULT_METHODS),
        help="Comma-separated ranking methods: tfidf, word2vec.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Evaluate only the first N cases.")
    parser.add_argument("--save", default="", help="Optional output directory for JSON/CSV/MD.")
    parser.add_argument("--json-only", action="store_true", help="Print JSON only.")
    args = parser.parse_args(argv)

    methods = [name.strip().lower() for name in args.methods.split(",") if name.strip()]
    if not methods:
        parser.error("at least one method is required")
    if args.limit < 0:
        parser.error("--limit must be >= 0")

    try:
        benchmark = load_capec_benchmark(_resolve(args.benchmark))
        from vuln2action.retrieval.capec import load_capec_index

        index = load_capec_index(_resolve(args.capec)) if args.capec else load_capec_index()
    except (OSError, ValueError, FileNotFoundError) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    if args.limit:
        benchmark = benchmark.model_copy(update={"cases": benchmark.cases[: args.limit]})

    model = None
    if "word2vec" in methods:
        try:
            model = train_word2vec(index)
        except MissingDependencyError as exc:
            parser.error(str(exc))
            return 2  # pragma: no cover - argparse exits

    report = evaluate(methods, benchmark, index, word2vec_model=model)
    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(_comparison_table(report))

    if args.save:
        run_dir = ensure_dir(
            _resolve(args.save) / f"capec_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        )
        write_json(run_dir / "report.json", report)
        (run_dir / "report.md").write_text(_markdown(report), encoding="utf-8")
        _write_csv(run_dir / "per_case.csv", report)
        print(f"report written under: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
