from __future__ import annotations

import json
from pathlib import Path

from scripts.build_hybrid_eval import main
from vuln2action.domain import CapecRecord, CapecStep
from vuln2action.utils.filesystem import read_json, write_json, write_jsonl


def _capec(capec_id: str, name: str, marker: str) -> CapecRecord:
    return CapecRecord(
        capec_id=capec_id,
        name=name,
        description=f"{name} description",
        execution_flow=[
            CapecStep(
                step=1,
                phase="Explore",
                description=f"[{marker}] Explore the target.",
                techniques=["probe"],
            ),
            CapecStep(
                step=2,
                phase="Experiment",
                description=f"[{marker}] Try the weakness.",
                techniques=["test"],
            ),
            CapecStep(
                step=3,
                phase="Exploit",
                description=f"[{marker}] Exploit the weakness.",
                techniques=["exploit"],
            ),
        ],
    )


def _write_fixture(root: Path) -> None:
    capecs = [
        _capec("CAPEC-66", "SQL Injection", "SQL"),
        _capec("CAPEC-7", "Blind SQL Injection", "Blind"),
    ]
    write_json(root / "capec.json", [capec.model_dump(mode="json") for capec in capecs])
    write_jsonl(
        root / "flow_dataset_eval_common1000" / "flow_validation.jsonl",
        [
            {
                "cve_id": "CVE-2024-0001",
                "capec_id": "CAPEC-66",
                "capec_name": "SQL Injection",
                "input": "SQL injection in the login form.",
                "target_steps": "dataset target",
            },
            {
                "cve_id": "CVE-2024-0002",
                "capec_id": "CAPEC-7",
                "capec_name": "Blind SQL Injection",
                "input": "Blind SQL injection in the search form.",
                "target_steps": "dataset target 2",
            },
        ],
    )
    write_jsonl(
        root / "predictions.jsonl",
        [
            {
                "cve_id": "CVE-2024-0001",
                "selected_capec_id": "CAPEC-66",
                "score": 0.9,
            },
            {
                "cve_id": "CVE-2024-0002",
                "selected_capec_id": "CAPEC-7",
                "score": 0.8,
            },
        ],
    )
    write_jsonl(
        root / "reference.jsonl",
        [
            {"cve_id": "CVE-2024-0001", "capec_ids": ["CAPEC-7"]},
            {"cve_id": "CVE-2024-0002", "capec_ids": ["CAPEC-7"]},
        ],
    )


def test_build_hybrid_eval_keeps_predicted_and_reference_views_separate(tmp_path: Path):
    _write_fixture(tmp_path)
    out = tmp_path / "out"
    assert (
        main(
            [
                "--base-dataset",
                str(tmp_path / "flow_dataset_eval_common1000"),
                "--predictions",
                str(tmp_path / "predictions.jsonl"),
                "--capec",
                str(tmp_path / "capec.json"),
                "--reference",
                str(tmp_path / "reference.jsonl"),
                "--out",
                str(out),
            ]
        )
        == 0
    )

    stats = read_json(out / "hybrid_stats.json")
    assert stats["views"]["common_predicted"] == 2
    assert stats["views"]["reference_predicted"] == 2
    assert stats["views"]["reference_predicted_correct"] == 1
    assert stats["predicted_in_independent_reference"] == 1

    common = [
        json.loads(line)
        for line in (out / "common_predicted" / "flow_validation.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    reference = [
        json.loads(line)
        for line in (out / "reference_predicted" / "flow_validation.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    assert common[0]["capec_id"] == "CAPEC-66"
    assert common[0]["target_steps"] == "dataset target"
    assert reference[0]["capec_id"] == "CAPEC-66"
    assert reference[0]["target_capec_id"] == "CAPEC-7"
    assert reference[0]["selection_correct"] is False
    assert "Blind" in reference[0]["target_steps"]
    assert reference[1]["selection_correct"] is True
    assert reference[1]["target_capec_id"] == "CAPEC-7"
