from __future__ import annotations

import json
from pathlib import Path

from vuln2action.domain import CapecRecord, CapecStep, CveRecord
from vuln2action.generation.flow_dataset import build_flow_dataset, enrich_flow_row
from vuln2action.mapping.exploit import ExploitMatch
from vuln2action.utils.filesystem import write_json, write_jsonl


def _build_dataset(root: Path) -> Path:
    cve = CveRecord(
        cve_id="CVE-2024-0001",
        description="SQL injection in a login form.",
    )
    capec = CapecRecord(
        capec_id="CAPEC-66",
        name="SQL Injection",
        description="An attacker injects SQL.",
        execution_flow=[
            CapecStep(
                step=1,
                phase="Explore",
                description="[Survey] Survey the login form.",
                techniques=["Spidering"],
            ),
            CapecStep(
                step=2,
                phase="Experiment",
                description="[Test] Try quote characters.",
                techniques=["Fuzzing"],
            ),
            CapecStep(
                step=3,
                phase="Exploit",
                description="[Exploit] Dump the user table.",
                techniques=["Union query"],
            ),
        ],
    )
    write_jsonl(root / "cves.jsonl", [cve.model_dump(mode="json")])
    write_json(root / "capec.json", [capec.model_dump(mode="json")])
    write_json(
        root / "splits.json",
        {
            "train": ["CVE-2024-0001"],
            "validation": [],
            "capec_eval_100": [],
            "human_eval_20": [],
        },
    )
    predictions = root / "predictions.jsonl"
    write_jsonl(
        predictions,
        [
            {
                "cve_id": "CVE-2024-0001",
                "method": "word2vec",
                "selected_capec_id": "CAPEC-66",
            }
        ],
    )
    return predictions


def test_build_flow_dataset_serialises_three_phases(tmp_path: Path):
    predictions = _build_dataset(tmp_path)
    out_dir = tmp_path / "flow"

    stats = build_flow_dataset(tmp_path, predictions, out_dir)

    assert stats["rows"] == 1
    assert stats["train"] == 1
    assert stats["validation"] == 0
    assert stats["unique_capec"] == 1
    assert stats["rows_with_all_phases"] == 1
    row = json.loads((out_dir / "flow_dataset.jsonl").read_text(encoding="utf-8"))
    assert row["cve_id"] == "CVE-2024-0001"
    assert row["target"].startswith("Explore: [Survey]")
    assert "Experiment: [Test]" in row["target"]
    assert "Exploit: [Exploit]" in row["target"]
    assert "Techniques: Spidering" in row["target"]
    assert row["target_techniques"].startswith("Explore: Spidering")
    assert row["step_count"] == 3
    assert row["technique_count"] == 3


def test_enrich_flow_row_replaces_techniques_with_exploit_descriptions():
    row = {
        "cve_id": "CVE-2024-0001",
        "phases": [
            {
                "phase": "Explore",
                "steps": [
                    {
                        "step": 1,
                        "description": "Survey the target.",
                        "techniques": ["Spidering"],
                    }
                ],
            },
            {"phase": "Experiment", "steps": []},
            {"phase": "Exploit", "steps": []},
        ],
    }
    mapping = {
        "Spidering": ExploitMatch(
            exploit_id="EDB-1",
            description="Crawl every link on the target application.",
            score=0.91,
        )
    }

    enriched = enrich_flow_row(row, mapping)

    assert "Crawl every link" in enriched["target_exploit"]
    assert "Crawl every link" in enriched["target_exploit_techniques"]
    assert enriched["exploits"][0]["exploit_id"] == "EDB-1"
    assert enriched["exploits"][0]["technique"] == "Spidering"
