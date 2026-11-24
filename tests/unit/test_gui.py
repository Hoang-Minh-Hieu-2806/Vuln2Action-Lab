from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("flask")

from gui.app import build_generation_view, create_app
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
    assert payload["flow"] == payload["reference_flow"]
    assert payload["generated_flow"] is None
    assert payload["generation_status"]["provider"] == "unavailable"
    assert payload["generation_status"]["status"] == "unavailable"
    assert payload["generation_status"]["reference_is_sample"] is False
    assert "not available" in payload["generation_status"]["reason"]


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
    assert b"Reference execution flow" in form.data
    assert b"not T5 output" in form.data
    assert b"Generation status:" in form.data
    assert b"unavailable (unavailable)" in form.data

    missing = client.get("/api/analyze?cve_id=CVE-9999-9999")
    assert missing.status_code == 400
    assert "unknown CVE" in missing.get_json()["error"]


def test_generation_view_reference_only():
    view = build_generation_view(
        provider="unavailable",
        status="unavailable",
        reason="reference only",
        reference_is_sample=True,
    )
    assert view["generated_flow"] is None
    assert view["status"] == "unavailable"
    assert view["reference_is_sample"] is True


def test_generation_view_generated_successfully():
    flow = [{"phase": "Explore", "steps": []}]
    view = build_generation_view(provider="t5", status="generated", generated_flow=flow)
    assert view["provider"] == "t5"
    assert view["status"] == "generated"
    assert view["generated_flow"] == flow


def test_generation_view_generated_requires_flow():
    with pytest.raises(ValueError):
        build_generation_view(provider="t5", status="generated")


def test_generation_view_failed_requires_reason():
    view = build_generation_view(provider="t5", status="failed", reason="checkpoint load failed")
    assert view["status"] == "failed"
    assert view["generated_flow"] is None
    with pytest.raises(ValueError):
        build_generation_view(provider="t5", status="failed")


def test_generation_view_not_generated():
    view = build_generation_view(provider="rule_based", status="not_generated")
    assert view["provider"] == "rule_based"
    assert view["status"] == "not_generated"
    assert view["generated_flow"] is None


def test_generation_view_sample_flow_is_not_generated():
    view = build_generation_view(
        provider="unavailable",
        status="sample_flow",
        reason="sample CAPEC flow",
        reference_is_sample=True,
    )
    assert view["status"] == "sample_flow"
    assert view["generated_flow"] is None
    assert view["reference_is_sample"] is True


def test_generation_view_t5_unavailable():
    view = build_generation_view(
        provider="t5", status="unavailable", reason="checkpoint unavailable"
    )
    assert view["provider"] == "t5"
    assert view["status"] == "unavailable"
    assert view["generated_flow"] is None


def test_generation_view_simulated_is_distinct_from_generated():
    flow = [{"phase": "Explore", "steps": []}]
    view = build_generation_view(
        provider="simulated",
        status="simulated",
        generated_flow=flow,
        reason="rule-based simulation",
    )
    assert view["provider"] == "simulated"
    assert view["status"] == "simulated"
    assert view["generated_flow"] == flow
    with pytest.raises(ValueError):
        build_generation_view(provider="simulated", status="generated", generated_flow=flow)
