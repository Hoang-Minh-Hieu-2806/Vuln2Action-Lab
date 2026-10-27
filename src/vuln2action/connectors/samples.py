"""Offline sample-data connector."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vuln2action.domain import CveRecord
from vuln2action.utils.filesystem import read_json, repo_path


def parse_cve_dict(raw: dict[str, Any]) -> CveRecord:
    return CveRecord.model_validate(raw)


def load_sample_cves(path: str | Path | None = None) -> list[CveRecord]:
    sample_path = Path(path) if path else repo_path("data", "samples", "sample_cves.json")
    records = read_json(sample_path)
    if not isinstance(records, list):
        raise TypeError(f"Expected a list of records in {sample_path}")
    return [parse_cve_dict(item) for item in records]


def get_sample_cve(cve_id: str, path: str | Path | None = None) -> CveRecord:
    for record in load_sample_cves(path):
        if record.cve_id == cve_id:
            return record
    raise KeyError(f"Sample CVE not found: {cve_id}")
