"""Generate human-evaluation case list and a header-filled reviewer form.

Requires the authoritative splits.json and never fills scores or reviewer data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from vuln2action.utils.filesystem import read_jsonl


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _header_value(lines: list[str], prefix: str, value: str) -> None:
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--splits", default="data/processed/reproduction/splits.json")
    parser.add_argument("--dataset-dir", default="data/processed/reproduction")
    parser.add_argument("--checkpoint", default="NOT_AVAILABLE")
    parser.add_argument("--provider", default="rule_based")
    parser.add_argument("--dataset-sha256", default="")
    parser.add_argument("--output-dir", default="docs/human-evaluation")
    args = parser.parse_args()

    splits_path = Path(args.splits)
    if not splits_path.is_file():
        parser.error(f"authoritative splits file not found: {splits_path}")
    splits = json.loads(splits_path.read_text(encoding="utf-8"))
    ids = splits.get("human_eval_20") or []
    if len(ids) != 20 or len(set(ids)) != 20:
        parser.error("splits.json must contain exactly 20 unique human_eval_20 ids")

    dataset_dir = Path(args.dataset_dir)
    cves = {row["cve_id"]: row for row in read_jsonl(dataset_dir / "cves.jsonl")}
    missing = [cve_id for cve_id in ids if cve_id not in cves]
    if missing:
        parser.error(f"CVEs missing from cves.jsonl: {missing}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cases = [
        {
            "case_id": index,
            "cve_id": cve_id,
            "description": cves[cve_id]["description"],
        }
        for index, cve_id in enumerate(ids, start=1)
    ]
    (output_dir / "cases_generated.json").write_text(
        json.dumps(cases, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    template = Path(__file__).resolve().parents[1] / "docs/human-evaluation/reviewer-form.md"
    lines = template.read_text(encoding="utf-8").splitlines(keepends=True)
    dataset_sha = args.dataset_sha256 or _sha256(dataset_dir / "cves.jsonl")
    _header_value(lines, "Dataset SHA-256: ", dataset_sha)
    _header_value(lines, "Checkpoint / model id: ", args.checkpoint)
    _header_value(lines, "Provider and generation settings: ", args.provider)

    blocks = [line for line in lines if not line.startswith("## Case 1 of 20")]
    head = "".join(blocks).rstrip() + "\n\n"
    for case in cases:
        head += (
            f"## Case {case['case_id']} of 20\n\n"
            f"CVE id: {case['cve_id']}\n\n"
            f"NVD description:\n\n{case['description']}\n\n"
            "Generated workflow:\n\n_____________________________________________________________\n\n"
            "| Criterion | 1 | 2 | 3 | 4 | 5 | Insufficient information | Not applicable | Cannot assess |\n"
            "|---|---|---|---|---|---|---|---|---|\n"
            "| Correctness |   |   |   |   |   |                          |                |               |\n"
            "| Completeness |   |   |   |   |   |                          |                |               |\n"
            "| Clarity |   |   |   |   |   |                          |                |               |\n\n"
            "Free-text comment:\n\n_____________________________________________________________\n\n"
            "Reference material (open after scoring):\n\n_____________________________________________________________\n\n"
        )
    (output_dir / "reviewer-form_generated.md").write_text(head, encoding="utf-8")
    print(f"cases={len(cases)} output={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
