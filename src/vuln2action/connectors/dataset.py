"""Build processed CVE/CWE/CAPEC datasets from opt-in local snapshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vuln2action.connectors.mitre import parse_capec_xml, parse_cwe_xml
from vuln2action.connectors.nvd import parse_nvd_records
from vuln2action.domain import CapecRecord, CveRecord, CweRecord
from vuln2action.utils.filesystem import read_json, write_json


def dedupe_cves(records: list[CveRecord]) -> list[CveRecord]:
    """Keep the last occurrence of each CVE id, preserving first-seen order."""
    latest: dict[str, CveRecord] = {}
    order: list[str] = []
    for record in records:
        if record.cve_id not in latest:
            order.append(record.cve_id)
        latest[record.cve_id] = record
    return [latest[cve_id] for cve_id in order]


def apply_lab_map(
    records: list[CveRecord],
    lab_map: dict[str, str] | None = None,
) -> list[CveRecord]:
    mapping = lab_map or {}
    if not mapping:
        return records
    updated: list[CveRecord] = []
    for record in records:
        lab_id = mapping.get(record.cve_id)
        if not lab_id or lab_id == record.lab_id:
            updated.append(record)
            continue
        updated.append(
            CveRecord.model_validate({**record.model_dump(mode="json"), "lab_id": lab_id})
        )
    return updated


def build_from_snapshots(
    snapshot_paths: list[str | Path],
    lab_map: dict[str, str] | None = None,
    include_rejected: bool = False,
) -> list[CveRecord]:
    records: list[CveRecord] = []
    for path in snapshot_paths:
        payload = read_json(path)
        records.extend(parse_nvd_records(payload, include_rejected=include_rejected))
    return apply_lab_map(dedupe_cves(records), lab_map)


def build_from_payload(
    payload: dict[str, Any],
    lab_map: dict[str, str] | None = None,
    include_rejected: bool = False,
) -> list[CveRecord]:
    records = parse_nvd_records(payload, include_rejected=include_rejected)
    return apply_lab_map(dedupe_cves(records), lab_map)


def load_lab_map(path: str | Path | None) -> dict[str, str]:
    if path is None:
        return {}
    raw = read_json(path)
    if not isinstance(raw, dict):
        raise TypeError(f"Lab map must be a JSON object: {path}")
    mapping: dict[str, str] = {}
    for cve_id, lab_id in raw.items():
        if not isinstance(cve_id, str) or not isinstance(lab_id, str):
            raise TypeError(f"Lab map entries must be strings: {path}")
        mapping[cve_id] = lab_id
    return mapping


def write_cve_dataset(records: list[CveRecord], path: str | Path) -> Path:
    return write_json(path, [record.model_dump(mode="json") for record in records])


def write_cwe_dataset(records: list[CweRecord], path: str | Path) -> Path:
    return write_json(path, [record.model_dump(mode="json") for record in records])


def write_capec_dataset(records: list[CapecRecord], path: str | Path) -> Path:
    return write_json(path, [record.model_dump(mode="json") for record in records])


def _load_list(path: str | Path) -> list[Any]:
    raw = read_json(path)
    if not isinstance(raw, list):
        raise TypeError(f"Expected a JSON list of records: {path}")
    return raw


def load_cve_dataset(path: str | Path) -> list[CveRecord]:
    return [CveRecord.model_validate(item) for item in _load_list(path)]


def load_cwe_dataset(path: str | Path) -> list[CweRecord]:
    return [CweRecord.model_validate(item) for item in _load_list(path)]


def load_capec_dataset(path: str | Path) -> list[CapecRecord]:
    return [CapecRecord.model_validate(item) for item in _load_list(path)]


def parse_catalogs(
    cwe_path: str | Path | None = None,
    capec_path: str | Path | None = None,
) -> tuple[list[CweRecord], list[CapecRecord]]:
    cwes = parse_cwe_xml(cwe_path) if cwe_path else []
    capecs = parse_capec_xml(capec_path) if capec_path else []
    return cwes, capecs
