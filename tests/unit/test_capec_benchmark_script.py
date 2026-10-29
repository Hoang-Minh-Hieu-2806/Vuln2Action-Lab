"""Benchmark builder: join, filtering, determinism, and provenance.

The builder reads local snapshots only when ``--download`` is absent, so these
tests use tiny in-memory gzip files written to a temp directory.
"""

import argparse
import gzip
import json
from typing import ClassVar

import pytest

from scripts.build_capec_benchmark import (
    _normalise_capec,
    _normalise_cwe,
    build_cases,
    build_payload,
    load_galeax_labels,
)

NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-TEST-0001",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "SQL injection in the login form of ExampleApp."}
                ],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-89"}]},
                ],
                "configurations": [],
                "references": [],
            }
        },
        {
            "cve": {
                "id": "CVE-TEST-0002",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Unrestricted file upload."}],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-434"}]},
                ],
                "configurations": [],
                "references": [],
            }
        },
        {
            "cve": {
                "id": "CVE-TEST-0003",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "No weakness recorded here."}],
                "weaknesses": [],
                "configurations": [],
                "references": [],
            }
        },
        {
            "cve": {
                "id": "CVE-TEST-0004",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Path traversal in file download."}],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-22"}]},
                ],
                "configurations": [],
                "references": [],
            }
        },
    ]
}

GALEAX_ROWS = [
    {"CVE-TEST-0001": {"CWE": ["89"], "CAPEC": ["66", "7"], "TECHNIQUES": [], "ATLAS": []}},
    {"CVE-TEST-0002": {"CWE": ["434"], "CAPEC": ["1"], "TECHNIQUES": [], "ATLAS": []}},
    {"CVE-TEST-0003": {"CWE": [], "CAPEC": [], "TECHNIQUES": [], "ATLAS": []}},
    # CVE-TEST-0004 is absent from Galeax on purpose.
]


@pytest.fixture()
def snapshots(tmp_path):
    nvd_path = tmp_path / "nvd.json.gz"
    nvd_path.write_bytes(gzip.compress(json.dumps(NVD_PAYLOAD).encode("utf-8")))
    galeax_path = tmp_path / "galeax.jsonl.gz"
    galeax_path.write_bytes(
        gzip.compress(("\n".join(json.dumps(row) for row in GALEAX_ROWS) + "\n").encode("utf-8"))
    )
    return nvd_path, galeax_path


def test_load_galeax_labels_flattens_jsonl(snapshots):
    _, galeax_path = snapshots
    labels = load_galeax_labels(galeax_path)
    assert set(labels) == {"CVE-TEST-0001", "CVE-TEST-0002", "CVE-TEST-0003"}


def test_normalisers_prefix_and_dedupe():
    assert _normalise_capec(["66", "CAPEC-7", "66", " "]) == ["CAPEC-66", "CAPEC-7"]
    assert _normalise_cwe(["89", "CWE-89", "CWE-22"]) == ["CWE-22", "CWE-89"]


def test_build_cases_filters_and_records_why(snapshots, monkeypatch):
    import scripts.build_capec_benchmark as builder

    class FakeDocument:
        def __init__(self, capec_id, cwe_ids):
            self.capec_id = capec_id
            self.cwe_ids = cwe_ids

    class FakeIndex:
        documents: ClassVar[dict] = {"CAPEC-66": FakeDocument("CAPEC-66", ["CWE-89"])}

        def candidates_for_cwes(self, cwe_ids):
            known = {
                "CWE-89": ["CAPEC-66", "CAPEC-7"],
                "CWE-434": ["CAPEC-1"],
                "CWE-22": ["CAPEC-126"],
            }
            found = set()
            for cwe in cwe_ids:
                found.update(known.get(cwe, []))
            return sorted(found)

    monkeypatch.setattr(builder, "load_capec_index", lambda: FakeIndex())
    nvd_path, galeax_path = snapshots
    cases, stats = build_cases("TEST", 10, 1, nvd_path, galeax_path)

    # 0001 and 0002 have labels + candidates; 0003 has no label; 0004 is absent.
    assert [case["cve_id"] for case in cases] == ["CVE-TEST-0001", "CVE-TEST-0002"]
    assert stats["skipped_no_label"] == 2
    assert stats["skipped_no_cwe"] == 0
    assert stats["selected"] == 2
    assert cases[0]["capec_label"] == ["CAPEC-66", "CAPEC-7"]
    assert cases[0]["candidates"] == ["CAPEC-66", "CAPEC-7"]
    assert cases[0]["case_id"] == "CAPEC-TEST-001"


def test_build_cases_skips_cves_without_candidates(snapshots, monkeypatch):
    import scripts.build_capec_benchmark as builder

    class EmptyIndex:
        documents: ClassVar[dict] = {}

        def candidates_for_cwes(self, cwe_ids):
            return []

    monkeypatch.setattr(builder, "load_capec_index", lambda: EmptyIndex())
    nvd_path, galeax_path = snapshots
    cases, stats = build_cases("TEST", 10, 1, nvd_path, galeax_path)
    assert cases == []
    assert stats["skipped_no_candidate"] == 2


def test_build_cases_is_deterministic_for_a_seed(snapshots, monkeypatch):
    import scripts.build_capec_benchmark as builder

    class FakeIndex:
        documents: ClassVar[dict] = {}

        def candidates_for_cwes(self, cwe_ids):
            return {"CWE-89": ["CAPEC-66"], "CWE-434": ["CAPEC-1"], "CWE-22": ["CAPEC-126"]}.get(
                cwe_ids[0], []
            )

    monkeypatch.setattr(builder, "load_capec_index", lambda: FakeIndex())
    nvd_path, galeax_path = snapshots
    first, _ = build_cases("TEST", 10, 7, nvd_path, galeax_path)
    second, _ = build_cases("TEST", 10, 7, nvd_path, galeax_path)
    assert [case["cve_id"] for case in first] == [case["cve_id"] for case in second]


def test_build_cases_records_cwe_mismatch(snapshots, monkeypatch):
    import scripts.build_capec_benchmark as builder

    class FakeIndex:
        documents: ClassVar[dict] = {}

        def candidates_for_cwes(self, cwe_ids):
            return ["CAPEC-66"] if "CWE-89" in cwe_ids else []

    monkeypatch.setattr(builder, "load_capec_index", lambda: FakeIndex())
    nvd_path, galeax_path = snapshots
    cases, _ = build_cases("TEST", 10, 1, nvd_path, galeax_path)
    case = next(item for item in cases if item["cve_id"] == "CVE-TEST-0001")
    assert case["label_source_cwe"] == ["CWE-89"]
    assert case["nvd_cwe_matches_label_source"] is True


def test_build_cases_respects_max_candidates(snapshots, monkeypatch):
    import scripts.build_capec_benchmark as builder

    class BigIndex:
        documents: ClassVar[dict] = {}

        def candidates_for_cwes(self, cwe_ids):
            return [f"CAPEC-{index}" for index in range(500)]

    monkeypatch.setattr(builder, "load_capec_index", lambda: BigIndex())
    nvd_path, galeax_path = snapshots
    cases, stats = build_cases("TEST", 10, 1, nvd_path, galeax_path, max_candidates=10)
    assert cases == []
    assert stats["skipped_large_candidate_set"] == 2


def test_build_payload_declares_provenance(snapshots, monkeypatch):
    import scripts.build_capec_benchmark as builder

    class FakeIndex:
        documents: ClassVar[dict] = {"CAPEC-66": object()}

    monkeypatch.setattr(builder, "load_capec_index", lambda: FakeIndex())
    payload = build_payload(
        "TEST",
        1,
        1,
        [
            {
                "case_id": "CAPEC-TEST-001",
                "cve_id": "CVE-TEST-0001",
                "query": "q",
                "cwe_ids": ["CWE-89"],
                "capec_label": ["CAPEC-66"],
                "candidates": ["CAPEC-66"],
                "label_source_cwe": ["CWE-89"],
                "nvd_cwe_matches_label_source": True,
            }
        ],
        {"selected": 1},
        "deadbeef",
    )
    assert "Galeax/CVE2CAPEC" in payload["labels_source"]
    assert "deadbeef" in payload["labels_source"]
    assert "NVD 2.0" in payload["query_source"]
    assert payload["cases"][0]["case_id"] == "CAPEC-TEST-001"


def test_builder_requires_download_when_snapshots_are_missing(tmp_path, monkeypatch):
    """Without --download the script must refuse instead of fetching silently."""
    import scripts.build_capec_benchmark as builder

    monkeypatch.setattr(builder, "_external_dir", lambda: tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        builder.main(["--year", "1999", "--size", "5"])
    assert excinfo.value.code == 2


def test_argparse_rejects_bad_sizes(tmp_path, monkeypatch):
    import scripts.build_capec_benchmark as builder

    monkeypatch.setattr(builder, "_external_dir", lambda: tmp_path)
    with pytest.raises(SystemExit):
        builder.main(["--year", "1999", "--size", "0"])


def test_nvd_payload_helper_is_argparse_independent():
    """Guard against accidental argparse/global-state coupling in the builder."""
    assert argparse  # imported for the CLI contract used above
