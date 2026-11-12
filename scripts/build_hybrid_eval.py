"""Build two-stage CVE -> CAPEC -> flow evaluation datasets.

The hybrid pipeline has two stages:

1. a CAPEC selector predicts a CAPEC from the CVE description;
2. the CAPEC-conditioned T5 model generates the execution flow.

The selector labels in ``flow_dataset`` were produced by the same Word2Vec
mapping, so evaluating the hybrid model on those rows would measure label
memorisation rather than selection quality.  This script therefore supports two
evaluation views:

* ``common``: the fixed 1,000-row baseline validation set, useful for a direct
  comparison with the CVE-only and gold-CAPEC runs;
* ``reference``: an independent CVE2CAPEC reference label, with its flow taken
  from CAPEC metadata, used to measure the real end-to-end pipeline.

The output directories each contain ``flow_validation.jsonl`` so they can be
passed directly to ``scripts/evaluate_t5.py``.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.domain import CapecRecord
from vuln2action.generation.flow_dataset import flow_targets
from vuln2action.mapping.ranking import capec_sort_key
from vuln2action.utils.filesystem import read_json, read_jsonl, write_json, write_jsonl


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _load_capecs(path: Path) -> dict[str, CapecRecord]:
    raw = read_json(path)
    return {record.capec_id: record for record in (CapecRecord.model_validate(row) for row in raw)}


def _load_predictions(path: Path) -> dict[str, dict[str, Any]]:
    predictions: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        cve_id = row.get("cve_id")
        if cve_id:
            predictions[cve_id] = row
    return predictions


def _load_references(path: Path) -> dict[str, list[str]]:
    references: dict[str, list[str]] = {}
    for row in read_jsonl(path):
        cve_id = row.get("cve_id")
        capec_ids = [str(item) for item in row.get("capec_ids") or []]
        if cve_id and capec_ids:
            references[cve_id] = capec_ids
    return references


def _reference_with_flow(
    capec_ids: list[str],
    capecs: dict[str, CapecRecord],
) -> tuple[str, CapecRecord] | None:
    """Pick one independent reference CAPEC that has a usable flow."""
    candidates = [
        capec_id
        for capec_id in capec_ids
        if capec_id in capecs and capecs[capec_id].execution_flow
    ]
    if not candidates:
        return None
    capec_id = min(candidates, key=capec_sort_key)
    return capec_id, capecs[capec_id]


def _row_for_input(
    base: dict[str, Any],
    input_capec: CapecRecord,
    target_capec: CapecRecord,
    *,
    cve_id: str,
    predicted_id: str | None,
    predicted_score: float,
    base_gold_id: str | None,
    reference_ids: list[str],
    input_source: str,
    target_source: str,
    selection_correct: bool | None = None,
    targets_override: dict[str, str] | None = None,
) -> dict[str, Any]:
    targets = targets_override or flow_targets(target_capec)
    return {
        "cve_id": cve_id,
        "capec_id": input_capec.capec_id,
        "capec_name": input_capec.name,
        "split": "validation",
        "input": base["input"],
        **targets,
        "phases": [],
        "step_count": len(target_capec.execution_flow),
        "technique_count": sum(
            len(step.techniques) for step in target_capec.execution_flow
        ),
        # Provenance fields are retained for auditing; evaluate_t5.py ignores them.
        "input_capec_id": input_capec.capec_id,
        "target_capec_id": target_capec.capec_id,
        "predicted_capec_id": predicted_id,
        "predicted_score": predicted_score,
        "dataset_gold_capec_id": base_gold_id,
        "reference_capec_ids": reference_ids,
        "selection_correct": selection_correct,
        "input_source": input_source,
        "target_source": target_source,
    }


def _write_view(out_dir: Path, rows: list[dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(out_dir / "flow_validation.jsonl", rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-dataset",
        default="data/processed/reproduction/flow_dataset_eval_common1000",
        help="Dataset containing flow_validation.jsonl with CVE descriptions.",
    )
    parser.add_argument(
        "--predictions",
        default=(
            "data/processed/reproduction/capec_selection/"
            "capec_predictions_word2vec_all.jsonl"
        ),
    )
    parser.add_argument(
        "--capec",
        default="data/processed/reproduction/capec.json",
    )
    parser.add_argument(
        "--reference",
        default="data/processed/reproduction/cve2capec_reference.jsonl",
    )
    parser.add_argument(
        "--out",
        default="data/processed/reproduction/hybrid_eval",
    )
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Randomly sample this many base rows. Defaults to the first --limit rows.",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    base_dir = _resolve(args.base_dataset)
    base_file = base_dir / "flow_validation.jsonl"
    if not base_file.is_file():
        parser.error(f"missing base validation split: {base_file}")

    capecs = _load_capecs(_resolve(args.capec))
    predictions = _load_predictions(_resolve(args.predictions))
    references = _load_references(_resolve(args.reference))
    base_rows = read_jsonl(base_file)
    if args.limit is not None:
        base_rows = base_rows[: args.limit]
    if args.sample_size is not None and args.sample_size < len(base_rows):
        rng = random.Random(args.seed)
        base_rows = rng.sample(base_rows, args.sample_size)

    common_predicted: list[dict[str, Any]] = []
    common_gold: list[dict[str, Any]] = []
    reference_predicted: list[dict[str, Any]] = []
    reference_predicted_correct: list[dict[str, Any]] = []
    reference_gold: list[dict[str, Any]] = []
    reference_cve_only: list[dict[str, Any]] = []
    skipped_no_prediction = 0
    skipped_no_reference = 0
    common_matches_gold = 0
    predicted_matches_reference = 0
    predicted_in_reference = 0

    for base in base_rows:
        cve_id = str(base["cve_id"])
        prediction = predictions.get(cve_id, {})
        predicted_id = prediction.get("selected_capec_id")
        predicted_score = float(prediction.get("score") or 0.0)
        base_gold_id = base.get("capec_id")
        base_gold = capecs.get(base_gold_id) if base_gold_id else None
        base_targets = {
            field: str(base.get(field) or "")
            for field in ("target", "target_steps", "target_techniques")
        }

        if base_gold is not None:
            common_gold.append(
                _row_for_input(
                    base,
                    base_gold,
                    base_gold,
                    cve_id=cve_id,
                    predicted_id=predicted_id,
                    predicted_score=predicted_score,
                    base_gold_id=base_gold_id,
                    reference_ids=references.get(cve_id, []),
                    input_source="dataset_gold",
                    target_source="dataset_gold",
                    targets_override=base_targets,
                )
            )

        if predicted_id and predicted_id in capecs and capecs[predicted_id].execution_flow:
            predicted = capecs[predicted_id]
            if predicted_id == base_gold_id:
                common_matches_gold += 1
            if base_gold is not None:
                common_predicted.append(
                    _row_for_input(
                        base,
                        predicted,
                        base_gold,
                        cve_id=cve_id,
                        predicted_id=predicted_id,
                        predicted_score=predicted_score,
                        base_gold_id=base_gold_id,
                        reference_ids=references.get(cve_id, []),
                        input_source="predicted",
                        target_source="dataset_gold",
                        targets_override=base_targets,
                    )
                )

            cve_references = references.get(cve_id, [])
            reference = _reference_with_flow(cve_references, capecs)
            if reference is None:
                skipped_no_reference += 1
                continue
            reference_id, reference_capec = reference
            selection_correct = predicted_id in cve_references
            if selection_correct:
                predicted_in_reference += 1
            if predicted_id == reference_id:
                predicted_matches_reference += 1

            # If the selector chose a valid reference CAPEC, evaluate generation
            # against that CAPEC's flow.  Otherwise fall back to the first valid
            # reference flow; the row is then a combined selection+generation
            # failure, which is what an end-to-end system would experience.
            target_capec = predicted if selection_correct else reference_capec
            target_id = target_capec.capec_id
            reference_predicted.append(
                _row_for_input(
                    base,
                    predicted,
                    target_capec,
                    cve_id=cve_id,
                    predicted_id=predicted_id,
                    predicted_score=predicted_score,
                    base_gold_id=base_gold_id,
                    reference_ids=cve_references,
                    input_source="predicted",
                    target_source="reference_or_predicted",
                    selection_correct=selection_correct,
                )
            )
            if selection_correct:
                reference_predicted_correct.append(
                    _row_for_input(
                        base,
                        predicted,
                        predicted,
                        cve_id=cve_id,
                        predicted_id=predicted_id,
                        predicted_score=predicted_score,
                        base_gold_id=base_gold_id,
                        reference_ids=cve_references,
                        input_source="predicted",
                        target_source="predicted",
                        selection_correct=True,
                    )
                )
            reference_gold.append(
                _row_for_input(
                    base,
                    reference_capec,
                    reference_capec,
                    cve_id=cve_id,
                    predicted_id=predicted_id,
                    predicted_score=predicted_score,
                    base_gold_id=base_gold_id,
                    reference_ids=cve_references,
                    input_source="reference_gold",
                    target_source="reference",
                    selection_correct=selection_correct,
                )
            )
            reference_cve_only.append(
                {
                    "cve_id": cve_id,
                    "capec_id": "",
                    "capec_name": "",
                    "split": "base",
                    "input": base["input"],
                    "target": base.get("target", ""),
                    **flow_targets(target_capec),
                    "predicted_capec_id": predicted_id,
                    "target_capec_id": target_id,
                    "reference_capec_ids": cve_references,
                    "selection_correct": selection_correct,
                    "input_source": "cve_only",
                    "target_source": "reference_or_predicted",
                }
            )
        else:
            skipped_no_prediction += 1

    out_dir = _resolve(args.out)
    views = {
        "common_predicted": common_predicted,
        "common_gold": common_gold,
        "reference_predicted": reference_predicted,
        "reference_predicted_correct": reference_predicted_correct,
        "reference_gold": reference_gold,
        "reference_cve_only": reference_cve_only,
    }
    for name, rows in views.items():
        _write_view(out_dir / name, rows)

    stats = {
        "base_dataset": str(base_dir),
        "predictions": str(_resolve(args.predictions)),
        "capec": str(_resolve(args.capec)),
        "reference": str(_resolve(args.reference)),
        "base_rows": len(base_rows),
        "views": {name: len(rows) for name, rows in views.items()},
        "skipped_no_prediction": skipped_no_prediction,
        "skipped_no_reference": skipped_no_reference,
        "common_predicted_equals_dataset_gold": common_matches_gold,
        "predicted_in_independent_reference": predicted_in_reference,
        "reference_predicted_equals_reference_target": predicted_matches_reference,
        "notes": [
            (
                "common_* compares against the existing flow_dataset labels, which were "
                "created by the same Word2Vec selector; use it only as an in-distribution "
                "check."
            ),
            (
                "reference_* uses independent CVE2CAPEC labels and CAPEC execution flows; "
                "use it for end-to-end hybrid evaluation."
            ),
            (
                "reference_cve_only has empty CAPEC fields and is intended for "
                "evaluate_t5.py --no-include-capec."
            ),
        ],
    }
    write_json(out_dir / "hybrid_stats.json", stats)
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
