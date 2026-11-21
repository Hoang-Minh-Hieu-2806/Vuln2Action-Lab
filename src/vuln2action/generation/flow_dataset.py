"""Build the T5 stage-1 dataset from selected CAPEC execution flows.

The paper serialises a CAPEC flow into three phases: Explore, Experiment, and
Exploit. Each phase may contain several steps and each step may contain several
techniques. We keep three target variants so the training script can choose a
length budget without losing the structured labels.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

from vuln2action.connectors.dataset import load_capec_dataset
from vuln2action.domain import CapecRecord, CapecStep, CveRecord
from vuln2action.mapping.exploit import ExploitMatch
from vuln2action.utils.filesystem import read_json, read_jsonl, write_json, write_jsonl

PHASES = ("Explore", "Experiment", "Exploit")


def _clean(text: str) -> str:
    return " ".join(text.split()).strip()


def phase_steps(capec: CapecRecord) -> dict[str, list[CapecStep]]:
    """Group CAPEC steps by the paper's three phases, preserving step order."""
    grouped: dict[str, list[CapecStep]] = {phase: [] for phase in PHASES}
    for step in capec.execution_flow:
        phase = step.phase.strip().title()
        if phase in grouped:
            grouped[phase].append(step)
    return grouped


def _step_with_techniques(step: CapecStep) -> str:
    description = _clean(step.description)
    techniques = [_clean(technique) for technique in step.techniques if _clean(technique)]
    if techniques:
        suffix = "; ".join(techniques)
        return f"{description} (Techniques: {suffix})".strip()
    return description


def flow_targets(capec: CapecRecord) -> dict[str, str]:
    """Return full, description-only, and technique-only targets."""
    grouped = phase_steps(capec)
    full_parts: list[str] = []
    step_parts: list[str] = []
    technique_parts: list[str] = []
    for phase in PHASES:
        steps = grouped[phase]
        full = " ".join(_step_with_techniques(step) for step in steps).strip()
        descriptions = " ".join(_clean(step.description) for step in steps).strip()
        techniques = "; ".join(
            _clean(technique)
            for step in steps
            for technique in step.techniques
            if _clean(technique)
        )
        full_parts.append(f"{phase}: {full}".strip())
        step_parts.append(f"{phase}: {descriptions}".strip())
        technique_parts.append(f"{phase}: {techniques}".strip())
    return {
        "target": " ".join(full_parts),
        "target_steps": " ".join(step_parts),
        "target_techniques": " ".join(technique_parts),
    }


def build_flow_row(cve: CveRecord, capec: CapecRecord, split: str) -> dict[str, Any]:
    grouped = phase_steps(capec)
    targets = flow_targets(capec)
    phases = [
        {
            "phase": phase,
            "steps": [
                {
                    "step": step.step,
                    "description": _clean(step.description),
                    "techniques": [_clean(technique) for technique in step.techniques],
                }
                for step in grouped[phase]
            ],
        }
        for phase in PHASES
    ]
    technique_count = sum(len(step.techniques) for step in capec.execution_flow)
    return {
        "cve_id": cve.cve_id,
        "capec_id": capec.capec_id,
        "capec_name": capec.name,
        "split": split,
        "input": cve.description,
        **targets,
        "phases": phases,
        "step_count": len(capec.execution_flow),
        "technique_count": technique_count,
    }


def _truncate_words(text: str, max_words: int) -> str:
    words = _clean(text).split()
    if len(words) <= max_words:
        return " ".join(words)
    return " ".join(words[:max_words]) + " ..."


def enrich_flow_row(
    row: dict[str, Any],
    mapping: dict[str, ExploitMatch],
    max_exploits_per_phase: int = 3,
    max_exploit_words: int = 40,
) -> dict[str, Any]:
    """Replace flow techniques with their closest ExploitDB descriptions."""
    full_parts: list[str] = []
    technique_parts: list[str] = []
    exploit_rows: list[dict[str, Any]] = []
    for phase in row["phases"]:
        phase_name = phase["phase"]
        step_texts: list[str] = []
        exploit_texts: list[str] = []
        for step in phase["steps"]:
            step_desc = _clean(step["description"])
            mapped_for_step: list[str] = []
            for technique in step["techniques"]:
                match = mapping.get(technique)
                if match is None:
                    mapped_for_step.append(technique)
                    continue
                description = _truncate_words(match.description, max_exploit_words)
                mapped_for_step.append(description)
                exploit_texts.append(description)
                exploit_rows.append(
                    {
                        "phase": phase_name,
                        "step": step["step"],
                        "technique": technique,
                        "exploit_id": match.exploit_id,
                        "score": match.score,
                        "description": match.description,
                    }
                )
            step_text = step_desc
            if mapped_for_step:
                step_text = f"{step_text} (Exploits: {'; '.join(mapped_for_step)})"
            step_texts.append(step_text)
        full_parts.append(f"{phase_name}: {' '.join(step_texts)}".strip())
        unique_exploits = list(dict.fromkeys(exploit_texts))[:max_exploits_per_phase]
        technique_parts.append(f"{phase_name}: {'; '.join(unique_exploits)}".strip())
    enriched = dict(row)
    enriched["target_exploit"] = " ".join(full_parts)
    enriched["target_exploit_techniques"] = " ".join(technique_parts)
    enriched["exploits"] = exploit_rows
    return enriched


def _load_predictions(path: Path) -> dict[str, str]:
    predictions: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            selected = row.get("selected_capec_id")
            if selected:
                predictions[row["cve_id"]] = selected
    return predictions


def build_flow_dataset(
    dataset_dir: str | Path,
    predictions_path: str | Path,
    out_dir: str | Path,
) -> dict[str, Any]:
    """Build train/validation stage-1 rows and return measured counts."""
    root = Path(dataset_dir)
    output = Path(out_dir)
    cves = {
        record.cve_id: record
        for record in (CveRecord.model_validate(row) for row in read_jsonl(root / "cves.jsonl"))
    }
    capecs = {record.capec_id: record for record in load_capec_dataset(root / "capec.json")}
    splits = read_json(root / "splits.json")
    predictions = _load_predictions(Path(predictions_path))

    rows: list[dict[str, Any]] = []
    no_prediction = 0
    no_flow = 0
    for split in ("train", "validation"):
        for cve_id in splits[split]:
            cve = cves.get(cve_id)
            capec_id = predictions.get(cve_id)
            capec = capecs.get(capec_id) if capec_id else None
            if cve is None or capec_id is None:
                no_prediction += 1
                continue
            if capec is None or not capec.execution_flow:
                no_flow += 1
                continue
            rows.append(build_flow_row(cve, capec, split))

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
    stats: dict[str, Any] = {
        "source_predictions": str(predictions_path),
        "rows": len(rows),
        "train": len(train_rows),
        "validation": len(validation_rows),
        "unique_capec": len({row["capec_id"] for row in rows}),
        "rows_with_all_phases": all_phases,
        "no_prediction": no_prediction,
        "no_execution_flow": no_flow,
        "mean_steps": statistics.mean(row["step_count"] for row in rows) if rows else 0.0,
        "mean_techniques": (
            statistics.mean(row["technique_count"] for row in rows) if rows else 0.0
        ),
        **target_stats,
    }

    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "flow_dataset.jsonl", rows)
    write_jsonl(output / "flow_train.jsonl", train_rows)
    write_jsonl(output / "flow_validation.jsonl", validation_rows)
    write_json(output / "flow_stats.json", stats)
    return stats
