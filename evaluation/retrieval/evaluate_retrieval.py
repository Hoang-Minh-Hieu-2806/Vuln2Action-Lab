"""Evaluate keyword, TF-IDF, and semantic retrieval on a CVE -> CWE benchmark.

Run::

    python scripts/run_evaluation.py --stage retrieval
    python scripts/run_evaluation.py --stage retrieval --corpus data/processed/cwe.json

Scores are computed from the benchmark's relevance judgements and the chosen
corpus; nothing is hard-coded.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from evaluation.retrieval.harness import evaluate, load_benchmark
from vuln2action.config import project_root
from vuln2action.retrieval import load_corpus_file, load_seed_corpus
from vuln2action.utils.filesystem import ensure_dir, write_json

DEFAULT_BENCHMARK = "evaluation/datasets/retrieval_benchmark.json"


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _table(report: dict[str, Any]) -> str:
    k = report["k"]
    lines = [
        (
            f"corpus: {report['corpus_documents']} documents | "
            f"benchmark: {report['benchmark_cases']} cases | k={k}"
        ),
        "",
        (
            f"{'backend':<10} {'P@' + str(k):>7} {'R@' + str(k):>7} "
            f"{'F1@' + str(k):>7} {'MRR':>7} {'MRR@' + str(k):>7} {'covered':>9}"
        ),
    ]
    for name, result in report["results"].items():
        lines.append(
            f"{name:<10} {result['precision']:>7.3f} {result['recall']:>7.3f} "
            f"{result['f1']:>7.3f} {result['mrr']:>7.3f} {result['mrr_at_k']:>7.3f} "
            f"{result['cases_fully_covered']:>4}/{result['cases_evaluated']:<4}"
        )
    return "\n".join(lines)


def _markdown(report: dict[str, Any]) -> str:
    k = report["k"]
    lines = [
        "# Retrieval evaluation",
        "",
        f"- Benchmark version: {report['benchmark_version']}",
        f"- Labels: {report['labels_source'] or 'n/a'}",
        f"- Corpus: {report['corpus_documents']} documents",
        f"- Cases: {report['benchmark_cases']}",
        f"- k: {k}",
        "",
        f"| Backend | P@{k} | R@{k} | F1@{k} | MRR | MRR@{k} | Fully covered |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, result in report["results"].items():
        lines.append(
            f"| {name} | {result['precision']:.3f} | {result['recall']:.3f} | "
            f"{result['f1']:.3f} | {result['mrr']:.3f} | {result['mrr_at_k']:.3f} | "
            f"{result['cases_fully_covered']}/{result['cases_evaluated']} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate retrieval backends.")
    parser.add_argument(
        "--benchmark",
        default=DEFAULT_BENCHMARK,
        help=f"Benchmark JSON (default: {DEFAULT_BENCHMARK}).",
    )
    parser.add_argument(
        "--corpus",
        default="",
        help="Corpus file: seed object or processed CWE list (default: tracked seed corpus).",
    )
    parser.add_argument(
        "--backends",
        default="keyword,tfidf,semantic",
        help="Comma-separated backend names (default: keyword,tfidf,semantic).",
    )
    parser.add_argument("--k", type=int, default=0, help="Cutoff (default: benchmark k).")
    parser.add_argument("--save", default="", help="Optional output directory for reports.")
    parser.add_argument("--json-only", action="store_true", help="Print JSON only.")
    args = parser.parse_args(argv)

    benchmark = load_benchmark(_resolve(args.benchmark))
    corpus = load_corpus_file(_resolve(args.corpus)) if args.corpus else load_seed_corpus()
    if not corpus:
        parser.error("retrieval corpus is empty")
    backends = [name.strip() for name in args.backends.split(",") if name.strip()]
    if not backends:
        parser.error("at least one backend is required")
    if args.k < 0:
        parser.error("--k must be >= 0")

    report = evaluate(backends, corpus, benchmark, k=args.k or None)
    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(_table(report))

    if args.save:
        run_dir = ensure_dir(
            _resolve(args.save) / f"retrieval_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        )
        write_json(run_dir / "report.json", report)
        (run_dir / "report.md").write_text(_markdown(report), encoding="utf-8")
        print(f"report written under: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
