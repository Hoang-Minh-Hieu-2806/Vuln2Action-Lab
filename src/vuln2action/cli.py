"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import subprocess

from vuln2action.config import load_settings
from vuln2action.connectors import get_sample_cve, load_sample_cves
from vuln2action.evidence import save_report
from vuln2action.pipeline import run_pipeline
from vuln2action.utils.logging import get_logger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Vuln2Action-Lab offline pipeline.")
    parser.add_argument("--sample", default="CVE-2024-0001", help="Sample identifier to run.")
    parser.add_argument("--provider", default=None, help="rule_based | llm | t5")
    parser.add_argument(
        "--retrieval",
        default=None,
        choices=["keyword", "tfidf", "semantic"],
        help="Retrieval backend (default from config/settings.yaml).",
    )
    parser.add_argument("--list-samples", action="store_true")
    parser.add_argument("--save", default="", help="Optional run id for a report directory.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Run the real isolated lab validator (requires Docker) instead of simulating.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print only machine-readable JSON without a verdict summary.",
    )
    args = parser.parse_args(argv)
    log = get_logger("vuln2action.cli")
    if args.list_samples:
        for record in load_sample_cves():
            print(f"{record.cve_id} ({record.lab_id}): {record.description[:80]}")
        return 0
    settings = load_settings()
    try:
        cve = get_sample_cve(args.sample)
        outcome = run_pipeline(
            cve,
            settings=settings,
            provider=args.provider,
            backend=args.retrieval,
            simulate=False if args.execute else None,
        )
    except (
        KeyError,
        NotImplementedError,
        ValueError,
        RuntimeError,
        FileNotFoundError,
        subprocess.SubprocessError,
    ) as exc:
        log.error(str(exc))
        return 2
    payload = outcome.to_dict()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if not args.json_only:
        print(
            f"\nVerdict for {cve.cve_id}: {outcome.result.status.value} "
            f"({outcome.result.steps_executed} steps, provider={outcome.provider})"
        )
    if args.save:
        paths = save_report(args.save, payload, output_dir=settings.evidence.output_dir)
        print(f"Report written under: {paths.run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
