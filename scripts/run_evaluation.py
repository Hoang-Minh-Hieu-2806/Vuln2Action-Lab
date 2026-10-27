"""Evaluation runner stub (Phase 7): dispatches per-stage harnesses."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run evaluation harnesses (Phase 7).")
    parser.add_argument(
        "--stage", default="retrieval", choices=["retrieval", "generation", "reproduction"]
    )
    args = parser.parse_args(argv)
    print(
        f"run_evaluation.py: stage '{args.stage}' not implemented in Phase 1 (no scores fabricated)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
