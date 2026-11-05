"""Build the stage-1 T5 flow dataset from Word2Vec-selected CAPECs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.generation.flow_dataset import build_flow_dataset


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/processed/reproduction")
    parser.add_argument(
        "--predictions",
        default=(
            "data/processed/reproduction/capec_selection/capec_predictions_word2vec_all.jsonl"
        ),
    )
    parser.add_argument("--out", default="data/processed/reproduction/flow_dataset")
    args = parser.parse_args(argv)

    stats = build_flow_dataset(
        dataset_dir=_resolve(args.dataset),
        predictions_path=_resolve(args.predictions),
        out_dir=_resolve(args.out),
    )
    print(
        f"rows={stats['rows']} train={stats['train']} validation={stats['validation']} "
        f"unique_capec={stats['unique_capec']} all_phases={stats['rows_with_all_phases']} "
        f"target_words_mean={stats['target_words_mean']:.1f}"
    )
    print(f"wrote flow dataset to {_resolve(args.out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
