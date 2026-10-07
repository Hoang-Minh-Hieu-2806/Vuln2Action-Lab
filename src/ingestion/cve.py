"""CVE ingestion: schemas + parsers for CVE records.

TODO(Phase 2): add NVD API client (opt-in, rate-limited) producing CveRecord.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CveRecord:
    """Normalised CVE record used across the pipeline."""

    cve_id: str
    description: str
    cvss: float | None = None
    cwe: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    lab_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "cpe": self.cpe,
            "references": self.references,
            "lab_id": self.lab_id,
        }


def parse_cve_dict(raw: dict[str, Any]) -> CveRecord:
    """Parse a raw dict (e.g. from sample_cves.json) into a CveRecord."""
    return CveRecord(
        cve_id=str(raw.get("cve_id", "UNKNOWN")),
        description=str(raw.get("description", "")),
        cvss=raw.get("cvss"),
        cwe=list(raw.get("cwe", [])),
        cpe=list(raw.get("cpe", [])),
        references=list(raw.get("references", [])),
        lab_id=str(raw.get("lab_id", "")),
    )


def load_sample_cves(path: str | Path | None = None) -> list[CveRecord]:
    """Load fake sample CVEs from data/samples/sample_cves.json."""
    import json

    if path is None:
        path = Path(__file__).resolve().parents[2] / "data" / "samples" / "sample_cves.json"
    with open(path, encoding="utf-8") as f:
        raw_list = json.load(f)
    return [parse_cve_dict(item) for item in raw_list]


def get_sample_cve(cve_id: str) -> CveRecord:
    """Return a single sample CVE by id (raises KeyError if missing)."""
    for record in load_sample_cves():
        if record.cve_id == cve_id:
            return record
    raise KeyError(f"Sample CVE not found: {cve_id}")
