"""Generate an Explore/Experiment/Exploit flow for one CVE with the local T5.

Examples::

    # Sample CVEs shipped with the repo
    python scripts/run_t5.py --sample CVE-2024-0002

    # Explicit description, using a fine-tuned checkpoint
    python scripts/run_t5.py --cve CVE-2021-44228 \
        --description "JNDI lookup injection in Log4j2" --cwe CWE-20 \
        --checkpoint models/t5-capec-flows

Output is *textual guidance*. It is not a validated exploit and the script never
touches a network target.
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

from vuln2action.config import load_model_settings
from vuln2action.domain import CveRecord
from vuln2action.generation.t5 import T5Generator, T5UnavailableError


def _safe_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def _build_cve(args: argparse.Namespace) -> CveRecord:
    if args.sample:
        from vuln2action.connectors import get_sample_cve

        return get_sample_cve(args.sample)
    if not args.cve or not args.description:
        raise ValueError("provide --sample, or both --cve and --description")
    return CveRecord(
        cve_id=args.cve,
        description=args.description,
        cwe=list(args.cwe or []),
    )


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(description="Generate an attack flow with local T5.")
    parser.add_argument("--sample", default="", help="Sample CVE id from data/samples.")
    parser.add_argument("--cve", default="", help="CVE id (with --description).")
    parser.add_argument("--description", default="", help="Vulnerability description.")
    parser.add_argument("--cwe", action="append", default=[], help="CWE id (repeatable).")
    parser.add_argument("--checkpoint", default="", help="Fine-tuned checkpoint directory.")
    parser.add_argument("--max-new-tokens", type=int, default=0, help="Override generation length.")
    parser.add_argument("--num-beams", type=int, default=0, help="Override beam count.")
    parser.add_argument(
        "--allow-download",
        action="store_true",
        help="Allow fetching the base checkpoint from the Hub if not cached.",
    )
    parser.add_argument("--json-only", action="store_true", help="Print the workflow as JSON.")
    args = parser.parse_args(argv)

    try:
        cve = _build_cve(args)
    except (KeyError, ValueError) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    settings = load_model_settings().providers.t5
    if args.checkpoint:
        settings = settings.model_copy(update={"checkpoint": args.checkpoint})
    if args.max_new_tokens:
        settings = settings.model_copy(update={"max_new_tokens": args.max_new_tokens})
    if args.num_beams:
        settings = settings.model_copy(update={"num_beams": args.num_beams})
    if args.allow_download:
        settings = settings.model_copy(update={"allow_download": True})

    generator = T5Generator(settings)
    try:
        workflow = generator.generate(cve, [])
    except T5UnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:  # optional stack missing
        print(f"error: {exc}", file=sys.stderr)
        return 2

    payload = workflow.model_dump(mode="json")
    if args.json_only:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(
        f"CVE: {workflow.cve_id}  provider={workflow.provider}  checkpoint={generator.checkpoint}"
    )
    print(f"safety: {workflow.safety}")
    print("-" * 70)
    for step in workflow.steps:
        print(f"[{step.id}] {step.action}")
        print(f"  {step.detail}")
    print("-" * 70)
    print("Generated guidance only - not a validated exploit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
