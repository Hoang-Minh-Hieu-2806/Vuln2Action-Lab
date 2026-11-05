"""Load the CVE/CAPEC tables used by best-CAPEC selection.

The selection stage only needs descriptions, candidate CAPEC ids, and the
evaluation-only CVE2CAPEC references. It never trains on those references.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from vuln2action.connectors.dataset import load_capec_dataset
from vuln2action.domain import CapecRecord, CveRecord
from vuln2action.utils.filesystem import read_json, read_jsonl


@dataclass(frozen=True)
class SelectionDataset:
    cves: dict[str, CveRecord]
    capecs: dict[str, CapecRecord]
    candidates: dict[str, tuple[str, ...]]
    references: dict[str, frozenset[str]]
    splits: dict[str, list[str]]


def _load_candidates(path: Path, known_capec_ids: set[str]) -> dict[str, tuple[str, ...]]:
    candidates: dict[str, set[str]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            capec_ids = set(row.get("candidate_capec_ids") or [])
            candidates.setdefault(row["cve_id"], set()).update(
                capec_id for capec_id in capec_ids if capec_id in known_capec_ids
            )
    return {cve_id: tuple(sorted(capec_ids)) for cve_id, capec_ids in candidates.items()}


def _load_references(path: Path) -> dict[str, frozenset[str]]:
    references: dict[str, frozenset[str]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            capec_ids = frozenset(row.get("capec_ids") or [])
            if capec_ids:
                references[row["cve_id"]] = capec_ids
    return references


def load_selection_dataset(dataset_dir: str | Path) -> SelectionDataset:
    """Load a dataset directory produced by ``build_reproduction_dataset.py``."""
    root = Path(dataset_dir)
    cves = {
        record.cve_id: record
        for record in (CveRecord.model_validate(row) for row in read_jsonl(root / "cves.jsonl"))
    }
    capecs = {record.capec_id: record for record in load_capec_dataset(root / "capec.json")}
    known_capec_ids = set(capecs)
    candidates = _load_candidates(root / "cve_capec_candidates.jsonl", known_capec_ids)
    references = _load_references(root / "cve2capec_reference.jsonl")
    splits = read_json(root / "splits.json")
    return SelectionDataset(
        cves=cves,
        capecs=capecs,
        candidates=candidates,
        references=references,
        splits=splits,
    )


def cve_selection_text(record: CveRecord) -> str:
    """Text compared against CAPEC descriptions for a CVE."""
    return record.description.strip()


def capec_selection_text(record: CapecRecord) -> str:
    """Text indexed as the CAPEC side of the similarity comparison."""
    name = record.name.strip()
    description = record.description.strip()
    if name and description:
        return f"{name}. {description}"
    return name or description
