from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("flask")

from gui.app import create_app
from vuln2action.domain import CapecRecord, CapecStep, CveRecord
from vuln2action.utils.filesystem import write_json, write_jsonl


def _build_dataset(root: Path) -> tuple[Path, Path]:
    cve = CveRecord(
        cve_id="CVE-2024-0001",
        description="SQL injection in the login form allows database commands.",
    )
    capec = CapecRecord(
        capec_id="CAPEC-66",
        name="SQL Injection",
        description="An attacker manipulates SQL queries.",
        execution_flow=[
            CapecStep(
                step=1,
                phase="Explore",
                description="Survey the login form.",
                techniques=["Spidering"],
            ),
            CapecStep(
                step=2,
                phase="Experiment",
                description="Try quote characters.",
                techniques=["Fuzzing"],
            ),
            CapecStep(
                step=3,
                phase="Exploit",
                description="Dump the user table.",
                techniques=["Union query"],
            ),
        ],
    )
    write_jsonl(root / "cves.jsonl", [cve.model_dump(mode="json")])
    write_json(root / "capec.json", [capec.model_dump(mode="json")])
    write_jsonl(
        root / "cve_capec_candidates.jsonl",
        [{"cve_id": "CVE-2024-0001", "cwe_id": "CWE-89", "candidate_capec_ids": ["CAPEC-66"]}],
    )
    write_jsonl(
        root / "cve2capec_reference.jsonl",
        [{"cve_id": "CVE-2024-0001", "capec_ids": ["CAPEC-66"]}],
    )
    write_json(
        root / "splits.json",
        {"train": ["CVE-2024-0001"], "validation": [], "capec_eval_100": [], "human_eval_20": []},
    )
    predictions = root / "predictions.jsonl"
    write_jsonl(
        predictions,
        [
            {
                "cve_id": "CVE-2024-0001",
                "method": "word2vec",
                "selected_capec_id": "CAPEC-66",
                "score": 0.9,
            }
        ],
    )
    technique_map = root / "technique_exploit_map.jsonl"
    write_jsonl(
        technique_map,
        [
            {
                "technique": "Spidering",
                "exploit_id": "EDB-1",
                "description": "Crawl links.",
                "score": 0.8,
            }
        ],
    )
    return predictions, technique_map


def test_gui_health_and_analyze_api(tmp_path: Path):
    predictions, technique_map = _build_dataset(tmp_path)
    app = create_app(tmp_path, predictions_path=predictions, technique_map_path=technique_map)
    client = app.test_client()

    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["cves"] == 1

    response = client.get("/api/analyze?cve_id=CVE-2024-0001")
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["selected_capec_id"] == "CAPEC-66"
    assert payload["flow"][0]["steps"][0]["techniques"][0]["exploit_id"] == "EDB-1"


def test_gui_form_and_unknown_cve(tmp_path: Path):
    predictions, technique_map = _build_dataset(tmp_path)
    app = create_app(tmp_path, predictions_path=predictions, technique_map_path=technique_map)
    client = app.test_client()

    page = client.get("/")
    assert page.status_code == 200
    assert b"Vuln2Action" in page.data

    form = client.post("/analyze", data={"cve_id": "CVE-2024-0001"})
    assert form.status_code == 200
    assert b"CAPEC-66" in form.data

    missing = client.get("/api/analyze?cve_id=CVE-9999-9999")
    assert missing.status_code == 400
    assert "unknown CVE" in missing.get_json()["error"]
