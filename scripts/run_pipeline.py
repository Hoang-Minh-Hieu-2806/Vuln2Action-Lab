"""CLI demo: sample CVE -> ingestion -> retrieval -> generation -> reproduction -> result.

Examples:
    python scripts/run_pipeline.py --sample CVE-2024-0001 --provider rule_based
    python scripts/run_pipeline.py --list-samples
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evidence.reporter import save_report  # noqa: E402
from src.ingestion.cve import get_sample_cve, load_sample_cves  # noqa: E402
from src.pipeline.pipeline import run_pipeline  # noqa: E402
from src.utils.logging import get_logger  # noqa: E402

log = get_logger("vuln2action.cli")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Vuln2Action-Lab sample pipeline.")
    parser.add_argument("--sample", default="CVE-2024-0001", help="Sample CVE id to run.")
    parser.add_argument("--provider", default="rule_based", help="rule_based | llm | t5")
    parser.add_argument("--list-samples", action="store_true", help="List sample CVEs and exit.")
    parser.add_argument("--save", default="", help="Optional run id to save JSON/MD report.")
    args = parser.parse_args(argv)

    if args.list_samples:
        for rec in load_sample_cves():
            print(f"{rec.cve_id}  ({rec.lab_id}): {rec.description[:80]}")
        return 0

    try:
        cve = get_sample_cve(args.sample)
    except KeyError as e:
        log.error(str(e))
        return 2
    try:
        out = run_pipeline(cve, provider=args.provider)
    except (NotImplementedError, ValueError) as e:
        log.error(str(e))
        return 3
    payload = out.to_dict()
    print(json.dumps(payload, indent=2))
    print(f"\nVerdict for {cve.cve_id}: {out.result.status.value} "
          f"({out.result.steps_executed} steps, provider={args.provider})")
    if args.save:
        paths = save_report(args.save, payload)
        print(f"Report written: {paths.json_path} + {paths.markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
