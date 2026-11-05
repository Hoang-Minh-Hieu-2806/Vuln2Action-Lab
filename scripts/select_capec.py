"""Select the best CAPEC for CVEs with TF-IDF or Word2Vec + cosine similarity."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.mapping import (
    SelectionDataset,
    TfidfCapecSelector,
    Word2VecCapecSelector,
    evaluate_selector,
    load_selection_dataset,
)
from vuln2action.utils.filesystem import write_json, write_jsonl


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _background_texts(dataset: SelectionDataset) -> list[str]:
    return [record.description for record in dataset.cves.values() if record.description.strip()]


def _build_selector(method: str, dataset: SelectionDataset, args: argparse.Namespace) -> Any:
    background = _background_texts(dataset)
    if method == "tfidf":
        return TfidfCapecSelector(dataset.capecs, background_texts=background)
    if method == "word2vec":
        return Word2VecCapecSelector(
            dataset.capecs,
            background_texts=background,
            vector_size=args.vector_size,
            window=args.window,
            epochs=args.epochs,
            seed=args.seed,
            workers=args.workers,
        )
    raise ValueError(f"unknown method: {method}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/processed/reproduction")
    parser.add_argument("--method", choices=["tfidf", "word2vec", "both"], default="tfidf")
    parser.add_argument("--scope", choices=["eval", "all"], default="eval")
    parser.add_argument("--split", default="capec_eval_100")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--out", default="")
    parser.add_argument("--vector-size", type=int, default=100)
    parser.add_argument("--window", type=int, default=5)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    dataset_dir = _resolve(args.dataset)
    dataset = load_selection_dataset(dataset_dir)
    if args.scope == "eval":
        cve_ids = dataset.splits[args.split]
    else:
        cve_ids = sorted(dataset.cves)

    out_dir = _resolve(args.out) if args.out else dataset_dir / "capec_selection"
    out_dir.mkdir(parents=True, exist_ok=True)

    methods = ["tfidf", "word2vec"] if args.method == "both" else [args.method]
    metrics: dict[str, Any] = {
        "scope": args.scope,
        "split": args.split if args.scope == "eval" else "all",
        "dataset": str(dataset_dir),
        "methods": {},
    }
    print(
        f"{'method':<9} {'split':<16} {'cves':>6} {'cand':>6} {'ref':>6} {'eval':>6} "
        f"{'correct':>8} {'acc':>8} {'acc_ans':>8} {'cand_rec':>9}"
    )
    for method in methods:
        selector = _build_selector(method, dataset, args)
        predictions, result = evaluate_selector(
            selector,
            dataset,
            split=args.split if args.scope == "eval" else "all",
            cve_ids=cve_ids,
            limit=args.limit,
        )
        metrics["methods"][method] = result.model_dump(mode="json")
        write_jsonl(
            out_dir / f"capec_predictions_{method}_{metrics['split']}.jsonl",
            [prediction.model_dump(mode="json") for prediction in predictions],
        )
        print(
            f"{method:<9} {result.split:<16} {result.cves:>6} {result.with_candidates:>6} "
            f"{result.with_reference:>6} {result.evaluated:>6} {result.correct:>8} "
            f"{result.accuracy:>7.2%} {result.accuracy_answered:>7.2%} "
            f"{result.candidate_recall:>8.2%}"
        )

    write_json(out_dir / f"capec_selection_metrics_{metrics['split']}.json", metrics)
    print(f"wrote CAPEC selection outputs to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
