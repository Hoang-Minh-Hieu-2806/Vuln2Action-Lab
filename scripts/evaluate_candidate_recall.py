"""Measure whether CWE-CAPEC candidates contain a CVE2CAPEC ground-truth CAPEC.

This is candidate recall, not the paper's best-CAPEC selection accuracy.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _load_candidates(path: Path) -> dict[str, set[str]]:
    candidates: dict[str, set[str]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            candidates.setdefault(row["cve_id"], set()).update(row.get("candidate_capec_ids") or [])
    return candidates


def _load_references(path: Path) -> dict[str, set[str]]:
    references: dict[str, set[str]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            capec_ids = set(row.get("capec_ids") or [])
            if capec_ids:
                references[row["cve_id"]] = capec_ids
    return references


def _score(
    cve_ids: list[str],
    candidates: dict[str, set[str]],
    references: dict[str, set[str]],
) -> dict[str, Any]:
    with_reference = [cve_id for cve_id in cve_ids if cve_id in references]
    hits = [
        cve_id for cve_id in with_reference if candidates.get(cve_id, set()) & references[cve_id]
    ]
    total = len(with_reference)
    return {
        "cves": len(cve_ids),
        "with_reference": total,
        "candidate_hits": len(hits),
        "recall": len(hits) / total if total else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default="data/processed/reproduction",
        help="Directory produced by build_reproduction_dataset.py.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON only.")
    args = parser.parse_args(argv)

    dataset = _resolve(args.dataset)
    splits = json.loads((dataset / "splits.json").read_text(encoding="utf-8"))
    candidates = _load_candidates(dataset / "cve_capec_candidates.jsonl")
    references = _load_references(dataset / "cve2capec_reference.jsonl")

    result: dict[str, Any] = {
        "capec_eval_100": _score(splits["capec_eval_100"], candidates, references),
        "human_eval_20": _score(splits["human_eval_20"], candidates, references),
        "all_references": _score(
            sorted(references),
            candidates,
            references,
        ),
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    print("Candidate recall (CVE2CAPEC ground truth, non-empty references only)")
    print(f"{'split':<18} {'with_ref':>8} {'hits':>6} {'recall':>8}")
    for name, row in result.items():
        print(
            f"{name:<18} {row['with_reference']:>8} "
            f"{row['candidate_hits']:>6} {row['recall']:>7.2%}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
