"""Evaluate TF-IDF retrieval (thin wrapper around the shared harness)."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from evaluation.retrieval.evaluate_retrieval import main as evaluate_main


def main(argv: list[str] | None = None) -> int:
    return evaluate_main(["--backends", "tfidf", *(argv or [])])


if __name__ == "__main__":
    raise SystemExit(main())
