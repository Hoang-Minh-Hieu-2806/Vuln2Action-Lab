"""Build an expanded stage-1 flow dataset without CAPEC in the model input.

The current flow dataset keeps only CVEs whose Word2Vec-selected CAPEC has an
execution flow. This script adds the remaining CVEs that have a CVE2CAPEC
reference CAPEC with an execution flow. Existing rows are kept unchanged by
default so the old and expanded runs can be compared directly.

Only the target is expanded. The T5 input remains the CVE description.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.connectors.dataset import load_capec_dataset
from vuln2action.domain import CapecRecord, CveRecord
from vuln2action.generation.flow_dataset import build_flow_row
from vuln2action.mapping import Word2VecCapecSelector
from vuln2action.utils.filesystem import read_json, read_jsonl, write_json, write_jsonl


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _load_references(path: Path, flow_ids: set[str]) -> dict[str, tuple[str, ...]]:
    """Load CVE2CAPEC IDs, keeping only CAPECs with an execution flow."""
    references: dict[str, tuple[str, ...]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            ids = tuple(
                dict.fromkeys(
                    capec_id
                    for capec_id in row.get("capec_ids", [])
                    if capec_id in flow_ids
                )
            )
            if ids:
                references[row["cve_id"]] = ids
    return references


def _load_selected(path: Path) -> dict[str, str]:
    selected: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            capec_id = row.get("selected_capec_id")
            if capec_id:
                selected[row["cve_id"]] = capec_id
    return selected


def _stats(rows: list[dict[str, Any]], extra: dict[str, Any]) -> dict[str, Any]:
    train_rows = [row for row in rows if row["split"] == "train"]
    validation_rows = [row for row in rows if row["split"] == "validation"]
    all_phases = sum(1 for row in rows if all(phase["steps"] for phase in row["phases"]))
    target_stats: dict[str, float | int] = {}
    for field in ("target", "target_steps", "target_techniques"):
        lengths = [len(row[field].split()) for row in rows]
        target_stats[f"{field}_words_mean"] = statistics.mean(lengths) if lengths else 0.0
        target_stats[f"{field}_words_p90"] = (
            sorted(lengths)[int(len(lengths) * 0.9)] if lengths else 0
        )
    return {
        **extra,
        "rows": len(rows),
        "train": len(train_rows),
        "validation": len(validation_rows),
        "unique_capec": len({row["capec_id"] for row in rows}),
        "rows_with_all_phases": all_phases,
        "mean_steps": statistics.mean(row["step_count"] for row in rows) if rows else 0.0,
        "mean_techniques": (
            statistics.mean(row["technique_count"] for row in rows) if rows else 0.0
        ),
        **target_stats,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/processed/reproduction")
    parser.add_argument(
        "--predictions",
        default=(
            "data/processed/reproduction/capec_selection/"
            "capec_predictions_word2vec_all.jsonl"
        ),
    )
    parser.add_argument("--out", default="data/processed/reproduction/flow_dataset_expanded")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional cap on processed CVEs per split for a smoke test.",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    root = _resolve(args.dataset)
    output = _resolve(args.out)
    cves = {
        record.cve_id: record
        for record in (CveRecord.model_validate(row) for row in read_jsonl(root / "cves.jsonl"))
    }
    capecs: dict[str, CapecRecord] = {
        record.capec_id: record for record in load_capec_dataset(root / "capec.json")
    }
    flow_capecs = {
        capec_id: capec for capec_id, capec in capecs.items() if capec.execution_flow
    }
    if not flow_capecs:
        raise SystemExit("no CAPEC with execution flow found")

    flow_ids = set(flow_capecs)
    splits = read_json(root / "splits.json")
    references = _load_references(root / "cve2capec_reference.jsonl", flow_ids)
    selected = _load_selected(_resolve(args.predictions))

    selector: Word2VecCapecSelector | None = None
    background = [record.description for record in cves.values() if record.description.strip()]

    rows: list[dict[str, Any]] = []
    counts = {
        "kept_existing": 0,
        "added_reference": 0,
        "no_prediction": 0,
        "no_flow": 0,
        "no_candidate": 0,
    }
    for split in ("train", "validation"):
        cve_ids = splits[split]
        if args.limit > 0:
            cve_ids = cve_ids[: args.limit]
        for cve_id in cve_ids:
            cve = cves.get(cve_id)
            if cve is None:
                counts["no_prediction"] += 1
                continue

            current = selected.get(cve_id)
            if current in flow_capecs:
                # Keep the original Word2Vec selection so the existing 55k rows
                # stay identical to the current baseline.
                capec_id = current
                counts["kept_existing"] += 1
            else:
                candidates = list(references.get(cve_id, ()))
                if not candidates:
                    counts["no_candidate"] += 1
                    continue
                if selector is None:
                    selector = Word2VecCapecSelector(
                        flow_capecs,
                        background_texts=background,
                        seed=args.seed,
                    )
                capec_id, _score = selector.select(cve.description, candidates)
                if capec_id is None:
                    counts["no_candidate"] += 1
                    continue
                counts["added_reference"] += 1

            capec = flow_capecs.get(capec_id)
            if capec is None:
                counts["no_flow"] += 1
                continue
            rows.append(build_flow_row(cve, capec, split))

    stats = _stats(
        rows,
        {
            "source_predictions": str(args.predictions),
            "source_reference": str(root / "cve2capec_reference.jsonl"),
            "flow_capec_catalog": len(flow_capecs),
            **counts,
        },
    )
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "flow_dataset.jsonl", rows)
    write_jsonl(
        output / "flow_train.jsonl", [row for row in rows if row["split"] == "train"]
    )
    write_jsonl(
        output / "flow_validation.jsonl",
        [row for row in rows if row["split"] == "validation"],
    )
    write_json(output / "flow_stats.json", stats)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"wrote expanded flow dataset to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
