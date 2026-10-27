"""Processed dataset building from NVD snapshots and lab maps."""

import pytest

from vuln2action.connectors.dataset import (
    apply_lab_map,
    build_from_payload,
    build_from_snapshots,
    dedupe_cves,
    load_cve_dataset,
    load_lab_map,
    parse_catalogs,
    write_cve_dataset,
)
from vuln2action.domain import CveRecord
from vuln2action.utils.filesystem import read_json, write_json


def _payload(*cve_ids: str) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": f"description for {cve_id}"}],
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                }
            }
            for cve_id in cve_ids
        ]
    }


def test_dedupe_keeps_last_record_and_first_order():
    first = CveRecord(cve_id="CVE-1", description="first")
    second = CveRecord(cve_id="CVE-2", description="second")
    replacement = CveRecord(cve_id="CVE-1", description="replacement")
    records = dedupe_cves([first, second, replacement])
    assert [record.cve_id for record in records] == ["CVE-1", "CVE-2"]
    assert records[0].description == "replacement"


def test_apply_lab_map_only_touches_mapped_records():
    records = [
        CveRecord(cve_id="CVE-1", description="one"),
        CveRecord(cve_id="CVE-2", description="two"),
    ]
    mapped = apply_lab_map(records, {"CVE-1": "cve-001"})
    assert mapped[0].lab_id == "cve-001"
    assert mapped[1].lab_id == ""


def test_build_from_payload_parses_and_maps():
    records = build_from_payload(
        _payload("CVE-2024-0001", "CVE-2024-0002"), {"CVE-2024-0002": "cve-002"}
    )
    assert [record.cve_id for record in records] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert records[1].lab_id == "cve-002"
    assert records[0].cwe == ["CWE-79"]


def test_build_from_snapshots_reads_directory_files(tmp_path):
    write_json(tmp_path / "one.json", _payload("CVE-1"))
    write_json(tmp_path / "two.json", _payload("CVE-1", "CVE-2"))
    files = sorted(tmp_path.glob("*.json"))
    records = build_from_snapshots(files)
    assert [record.cve_id for record in records] == ["CVE-1", "CVE-2"]


def test_write_cve_dataset_round_trip(tmp_path):
    records = [CveRecord(cve_id="CVE-1", description="one")]
    path = write_cve_dataset(records, tmp_path / "cves.json")
    raw = read_json(path)
    assert raw == [records[0].model_dump(mode="json")]
    assert load_cve_dataset(path) == records


def test_load_lab_map_validates_shape(tmp_path):
    good = tmp_path / "map.json"
    write_json(good, {"CVE-1": "cve-001"})
    assert load_lab_map(good) == {"CVE-1": "cve-001"}
    assert load_lab_map(None) == {}

    bad = tmp_path / "bad.json"
    write_json(bad, ["not", "a", "map"])
    with pytest.raises(TypeError):
        load_lab_map(bad)


def test_parse_catalogs_handles_missing_inputs():
    assert parse_catalogs() == ([], [])
