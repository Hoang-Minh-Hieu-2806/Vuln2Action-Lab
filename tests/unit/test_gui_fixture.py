"""GUI smoke test with a temporary fixture built from tracked samples only."""

import json
from pathlib import Path

import pytest

pytest.importorskip("flask")

from gui.app import create_app
from vuln2action.domain import CapecRecord, CapecStep

ROOT = Path(__file__).resolve().parents[2]


def _write_fixture(root: Path) -> None:
    samples = json.loads((ROOT / "data/samples/sample_cves.json").read_text(encoding="utf-8"))
    capec = CapecRecord(
        capec_id="CAPEC-591",
        name="Reflected XSS",
        description="Demo CAPEC for the sample XSS CVE.",
        related_cwe_ids=["CWE-79"],
        execution_flow=[
            CapecStep(
                step=1,
                phase="Explore",
                description="Find the reflected query parameter.",
                techniques=["Probe query parameter q"],
            )
        ],
    )
    root.mkdir(parents=True, exist_ok=True)
    (root / "cves.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in samples),
        encoding="utf-8",
    )
    (root / "capec.json").write_text(
        json.dumps([capec.model_dump(mode="json")], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (root / "cve_capec_candidates.jsonl").write_text(
        "".join(
            json.dumps(
                {"cve_id": row["cve_id"], "candidate_capec_ids": ["CAPEC-591"]},
                ensure_ascii=False,
            )
            + "\n"
            for row in samples
        ),
        encoding="utf-8",
    )
    (root / "cve2capec_reference.jsonl").write_text("", encoding="utf-8")
    splits = {
        "train": [row["cve_id"] for row in samples],
        "validation": [],
        "capec_eval_100": [],
        "human_eval_20": [],
    }
    (root / "splits.json").write_text(
        json.dumps(splits, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def test_gui_fixture_routes(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "reproduction"
    _write_fixture(dataset_dir)
    client = create_app(dataset_dir=dataset_dir).test_client()

    assert client.get("/").status_code == 200
    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["cves"] == 3
    assert health.get_json()["capecs"] == 1

    analyzed = client.get("/api/analyze?cve_id=CVE-2024-0001")
    assert analyzed.status_code == 200
    assert analyzed.get_json()["selected_capec_id"] == "CAPEC-591"
