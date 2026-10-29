"""Independent CVE -> CAPEC evaluation (MITRE example labels, not CWE closure).

This harness answers the question the tracked 120-CVE benchmark cannot: does the
ranking actually pick the right attack pattern when the ground truth was **not**
derived from the same CWE->CAPEC relation used to build the candidates?

Labels come from MITRE CAPEC ``Example_Instances`` (see
``scripts/build_capec_independent.py``), each stored with the verbatim sentence
that justifies it. Ranking code and metric definitions are reused from
:mod:`evaluation.retrieval.evaluate_capec` unchanged, so both benchmarks share
one implementation and the comparison is apples-to-apples.

Reported splits matter here:

``all``            every labelled case. Unreachable cases count as misses, which
                   is honest: the candidate generator never offered the label.
``reachable``      only cases whose MITRE label appears in the CWE-derived
                   candidate pool, i.e. the cases this architecture could,
                   in principle, answer.
``coverage``       share of cases whose label is reachable at all. This is the
                   structural recall ceiling of CWE->CAPEC candidate expansion.

A case may also be ``unlabeled`` (label withheld pending review). Unlabelled cases
are listed for annotation and excluded from every metric instead of being scored
as failures.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ROOT = Path(__file__).resolve().parents[2]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from evaluation.retrieval.evaluate_capec import (
    CapecBenchmarkCase,
    evaluate_method,
    summarise_rows,
)
from vuln2action.config import project_root
from vuln2action.retrieval.capec import (
    MissingDependencyError,
    load_capec_index,
    train_word2vec,
)
from vuln2action.utils.filesystem import ensure_dir, read_json, write_json

DEFAULT_BENCHMARK = "evaluation/datasets/capec_independent.json"
DEFAULT_METHODS = ("tfidf", "word2vec")

VERIFIED_STATUSES = {"mitre-evidence", "reviewed-accepted"}


class LabelEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capec_id: str
    capec_name: str = ""
    text: str = ""


class IndependentCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    cve_id: str
    query: str
    cwe_ids: list[str] = Field(default_factory=list)
    cwe_source: str = "nvd"
    capec_label: list[str] = Field(default_factory=list)
    candidates: list[str] = Field(default_factory=list)
    label_evidence: list[LabelEvidence] = Field(default_factory=list)
    label_reachable_in_candidates: list[str] = Field(default_factory=list)
    label_fully_reachable: bool = False
    # Review workflow: "mitre-evidence" until a human accepts or rejects it.
    review_status: str = "mitre-evidence"
    review_note: str = ""

    @field_validator("capec_label", "candidates", "cwe_ids", "label_reachable_in_candidates")
    @classmethod
    def normalise_ids(cls, values: list[str]) -> list[str]:
        seen: list[str] = []
        for value in values:
            text = str(value).strip().upper()
            if text and text not in seen:
                seen.append(text)
        return seen

    @property
    def is_labeled(self) -> bool:
        return bool(self.capec_label) and self.review_status in VERIFIED_STATUSES

    def to_benchmark_case(self) -> CapecBenchmarkCase:
        return CapecBenchmarkCase(
            case_id=self.case_id,
            cve_id=self.cve_id,
            query=self.query,
            cwe_ids=self.cwe_ids,
            capec_label=self.capec_label,
            candidates=self.candidates,
        )


class IndependentBenchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0.0"
    kind: str = "independent"
    description: str = ""
    labels_source: str = ""
    query_source: str = ""
    candidate_source: str = ""
    labeling_criteria: str = ""
    uncertainty: str = ""
    built_at: str = ""
    sample_stats: dict[str, Any] = Field(default_factory=dict)
    k: int = Field(default=1, ge=1)
    cases: list[IndependentCase] = Field(min_length=1)


def load_independent_benchmark(path: str | Path) -> IndependentBenchmark:
    return IndependentBenchmark.model_validate(read_json(path))


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _evaluate_subset(
    method: str,
    benchmark: IndependentBenchmark,
    index,
    case_ids: set[str],
    word2vec_model=None,
) -> dict[str, Any]:
    """Run one method on the selected cases and aggregate the existing metrics."""
    selected = [case for case in benchmark.cases if case.case_id in case_ids]
    surrogate = SimpleNamespace(cases=[case.to_benchmark_case() for case in selected])
    rows = evaluate_method(method, surrogate, index, word2vec_model=word2vec_model)
    summary = summarise_rows(rows)
    failures = [
        {
            "case_id": row["case_id"],
            "cve_id": row["cve_id"],
            "predicted": row["predicted"] or None,
            "hit_rank": row["hit_rank"],
            "candidates": row["candidates"],
            "reason": "no ranking (no shared vocabulary)" if not row["ranked"] else "wrong top-1",
        }
        for row in rows
        if row["membership_correct"] == 0.0
    ]
    return {**summary, "rows": rows, "failures": failures}


def evaluate_independent(
    methods: Sequence[str],
    benchmark: IndependentBenchmark,
    index,
    word2vec_model=None,
) -> dict[str, Any]:
    labeled = {case.case_id for case in benchmark.cases if case.is_labeled}
    unlabeled = {case.case_id for case in benchmark.cases if not case.is_labeled}
    reachable = {
        case.case_id
        for case in benchmark.cases
        if case.is_labeled and set(case.capec_label) <= set(case.candidates)
    }
    unreachable = labeled - reachable

    results: dict[str, Any] = {}
    for method in methods:
        all_rows = _evaluate_subset(method, benchmark, index, labeled, word2vec_model)
        reach_rows = _evaluate_subset(method, benchmark, index, reachable, word2vec_model)
        results[method] = {
            "method": method,
            "all": all_rows,
            "reachable": reach_rows,
            "unreachable_case_ids": sorted(unreachable),
        }

    return {
        "benchmark_version": benchmark.version,
        "labels_source": benchmark.labels_source,
        "query_source": benchmark.query_source,
        "candidate_source": benchmark.candidate_source,
        "labeling_criteria": benchmark.labeling_criteria,
        "uncertainty": benchmark.uncertainty,
        "total_cases": len(benchmark.cases),
        "labeled_cases": len(labeled),
        "unlabeled_case_ids": sorted(unlabeled),
        "reachable_cases": len(reachable),
        "unreachable_cases": len(unreachable),
        "coverage": (len(reachable) / len(labeled)) if labeled else 0.0,
        "capec_catalog": len(index.documents),
        "generated_at": datetime.now(UTC).isoformat(),
        "results": results,
    }


def _table(report: dict[str, Any]) -> str:
    lines = [
        (
            f"cases: {report['total_cases']} ({report['labeled_cases']} labelled, "
            f"{len(report['unlabeled_case_ids'])} unlabelled) | "
            f"label reachable in candidates: {report['reachable_cases']}"
            f"/{report['labeled_cases']} (coverage {report['coverage']:.3f})"
        ),
        "",
        f"{'method':<10} {'split':<10} {'top1':>7} {'R@5':>7} {'MRR':>7} {'cwe-cov':>8} {'empty':>6} {'n':>4}",
    ]
    for name, result in report["results"].items():
        for split in ("all", "reachable"):
            block = result[split]
            disc = block["discriminative"]
            lines.append(
                f"{name:<10} {split:<10} {block['membership']['top_1_accuracy']:>7.4f} "
                f"{disc['recall_at_5']:>7.4f} {disc['mrr']:>7.4f} "
                f"{disc['top_1_cwe_coverage']:>8.4f} {block['empty_rankings']:>6} "
                f"{block['cases']:>4}"
            )
    lines.append("")
    lines.append("Failures (all labelled cases):")
    for name, result in report["results"].items():
        for failure in result["all"]["failures"]:
            lines.append(
                f"  {name:<10} {failure['cve_id']:<16} rank={failure['hit_rank'] or '-'} "
                f"pred={failure['predicted'] or '-'} ({failure['reason']})"
            )
    return "\n".join(lines)


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Independent CVE -> CAPEC evaluation",
        "",
        f"- Total cases: {report['total_cases']}",
        f"- Labelled: {report['labeled_cases']} (unlabelled: {len(report['unlabeled_case_ids'])})",
        (
            f"- Label reachable in candidates: {report['reachable_cases']} "
            f"({report['coverage']:.1%})"
        ),
        f"- CAPEC catalog: {report['capec_catalog']} patterns",
        f"- Queries: {report['query_source']}",
        f"- Labels: {report['labels_source']}",
        "",
        "`all` counts unreachable cases as misses. `reachable` keeps only cases whose",
        "MITRE label is inside the CWE-derived candidate pool.",
        "",
        "| Method | Split | Top-1 | R@5 | MRR | Top-1 CWE cov. | Empty | n |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, result in report["results"].items():
        for split in ("all", "reachable"):
            block = result[split]
            disc = block["discriminative"]
            lines.append(
                f"| {name} | {split} | {block['membership']['top_1_accuracy']:.4f} | "
                f"{disc['recall_at_5']:.4f} | {disc['mrr']:.4f} | "
                f"{disc['top_1_cwe_coverage']:.4f} | {block['empty_rankings']} | {block['cases']} |"
            )
    lines.extend(["", "## Failure cases", ""])
    for name, result in report["results"].items():
        for failure in result["all"]["failures"]:
            lines.append(
                f"- `{name}` {failure['cve_id']}: predicted "
                f"{failure['predicted'] or 'nothing'} (hit rank {failure['hit_rank'] or 'miss'})"
            )
    if report["unlabeled_case_ids"]:
        lines.extend(["", "## Awaiting review (excluded from metrics)", ""])
        lines.extend(f"- {case_id}" for case_id in report["unlabeled_case_ids"])
    return "\n".join(lines) + "\n"


def _write_csv(path: Path, report: dict[str, Any]) -> Path:
    fieldnames = [
        "method",
        "split",
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
        "recall_at_5",
        "graded_top1",
        "ndcg",
    ]
    row_fields = [name for name in fieldnames if name not in {"method", "split"}]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for method, result in report["results"].items():
            for row in result["all"]["rows"]:
                writer.writerow(
                    {
                        "method": method,
                        "split": "all",
                        **{key: row.get(key, "") for key in row_fields},
                    }
                )
    return path


def _safe_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(
        description="Evaluate CVE -> CAPEC on the independent MITRE-label benchmark."
    )
    parser.add_argument(
        "--benchmark",
        default=DEFAULT_BENCHMARK,
        help=f"Independent benchmark JSON (default: {DEFAULT_BENCHMARK}).",
    )
    parser.add_argument("--capec", default="", help="CAPEC XML snapshot path.")
    parser.add_argument(
        "--methods",
        default=",".join(DEFAULT_METHODS),
        help="Comma-separated ranking methods (tfidf, word2vec).",
    )
    parser.add_argument("--save", default="", help="Optional output directory.")
    parser.add_argument("--json-only", action="store_true", help="Print JSON only.")
    args = parser.parse_args(argv)

    methods = [name.strip().lower() for name in args.methods.split(",") if name.strip()]
    if not methods:
        parser.error("at least one method is required")

    try:
        benchmark = load_independent_benchmark(_resolve(args.benchmark))
        index = load_capec_index(_resolve(args.capec) if args.capec else None)
    except (OSError, ValueError, FileNotFoundError) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    if not any(case.is_labeled for case in benchmark.cases):
        parser.error("benchmark has no labelled cases to evaluate")

    model = None
    if "word2vec" in methods:
        try:
            model = train_word2vec(index)
        except MissingDependencyError as exc:
            parser.error(str(exc))
            return 2  # pragma: no cover - argparse exits

    report = evaluate_independent(methods, benchmark, index, word2vec_model=model)
    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(_table(report))

    if args.save:
        run_dir = ensure_dir(
            _resolve(args.save)
            / f"capec_independent_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        )
        write_json(run_dir / "report.json", report)
        (run_dir / "report.md").write_text(_markdown(report), encoding="utf-8")
        _write_csv(run_dir / "per_case.csv", report)
        print(f"report written under: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
