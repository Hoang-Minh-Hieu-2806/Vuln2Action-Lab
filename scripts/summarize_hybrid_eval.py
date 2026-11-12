"""Summarize hybrid evaluation runs produced by ``scripts/evaluate_t5.py``.

The script is intentionally read-only: it never runs a model and never touches
exploit code.  It is useful after downloading the Kaggle kernel output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _load_metrics(run_dir: Path) -> dict[str, object] | None:
    path = run_dir / "metrics.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs-root",
        default="data/external/hybrid_eval_run_v3",
        help="Directory containing <view>/metrics.json outputs.",
    )
    parser.add_argument("--out", default=None, help="Optional JSON output path.")
    args = parser.parse_args(argv)

    root = _resolve(args.runs_root)
    if not root.is_dir():
        parser.error(f"missing runs root: {root}")

    summary: dict[str, object] = {}
    for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        metrics = _load_metrics(run_dir)
        if metrics is None:
            continue
        summary[run_dir.name] = {
            "rows": metrics.get("rows"),
            "bleu": metrics.get("bleu"),
            "bleu_corpus": metrics.get("bleu_corpus"),
            "rouge1_f1": metrics.get("rouge1_f1"),
            "rouge2_f1": metrics.get("rouge2_f1"),
            "rougeL_f1": metrics.get("rougeL_f1"),
            "include_capec": metrics.get("include_capec"),
            "target_field": metrics.get("target_field"),
        }

    if not summary:
        parser.error(f"no metrics.json found under {root}")

    print(
        f"{'view':42s} {'rows':>6s} {'BLEU':>8s} {'R1-F1':>8s} "
        f"{'R2-F1':>8s} {'RL-F1':>8s}"
    )
    for name, values in summary.items():
        print(
            f"{name:42s} {int(values['rows']):6d} "
            f"{float(values['bleu']):8.4f} {float(values['rouge1_f1']):8.4f} "
            f"{float(values['rouge2_f1']):8.4f} {float(values['rougeL_f1']):8.4f}"
        )

    if args.out:
        out = _resolve(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
