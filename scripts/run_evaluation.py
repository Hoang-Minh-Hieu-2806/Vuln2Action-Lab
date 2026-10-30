"""Evaluation runner: dispatches per-stage harnesses (Phase 3/7)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run evaluation harnesses.", add_help=False)
    parser.add_argument(
        "--stage",
        default="retrieval",
        choices=["retrieval", "capec", "capec-independent", "generation", "reproduction"],
    )
    parser.add_argument("-h", "--help", action="store_true", dest="show_help")
    args, rest = parser.parse_known_args(argv)
    if args.stage == "retrieval":
        from evaluation.retrieval.evaluate_retrieval import main as run_retrieval

        return run_retrieval([*rest, "--help"] if args.show_help else rest)
    if args.stage == "capec":
        from evaluation.retrieval.evaluate_capec import main as run_capec

        return run_capec([*rest, "--help"] if args.show_help else rest)
    if args.stage == "capec-independent":
        from evaluation.retrieval.evaluate_capec_independent import main as run_independent

        return run_independent([*rest, "--help"] if args.show_help else rest)
    if args.stage == "generation":
        from evaluation.generation.evaluate_generation import main as run_generation

        return run_generation([*rest, "--help"] if args.show_help else rest)
    if args.show_help:
        parser.print_help()
        return 0
    print(f"run_evaluation.py: stage '{args.stage}' is not implemented yet (Phase 7).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
