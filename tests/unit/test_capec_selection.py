from __future__ import annotations

from pathlib import Path

import pytest

from vuln2action.domain import CapecRecord, CveRecord
from vuln2action.mapping import (
    TfidfCapecSelector,
    Word2VecCapecSelector,
    evaluate_selector,
    load_selection_dataset,
)
from vuln2action.utils.filesystem import write_json, write_jsonl


def _build_dataset(root: Path) -> Path:
    cves = [
        CveRecord(
            cve_id="CVE-2024-0001",
            description="SQL injection in the login form allows arbitrary database commands.",
        ),
        CveRecord(
            cve_id="CVE-2024-0002",
            description="A buffer overflow in the image parser causes memory corruption.",
        ),
        CveRecord(
            cve_id="CVE-2024-0003",
            description="Path traversal lets an attacker read files outside the web root.",
        ),
    ]
    capecs = [
        CapecRecord(
            capec_id="CAPEC-66",
            name="SQL Injection",
            description="An attacker manipulates SQL queries to run database commands.",
        ),
        CapecRecord(
            capec_id="CAPEC-100",
            name="Overflow Buffers",
            description="An attacker sends too much data to a buffer and corrupts memory.",
        ),
        CapecRecord(
            capec_id="CAPEC-126",
            name="Path Traversal",
            description="An attacker uses dot dot slash sequences to read outside files.",
        ),
    ]
    write_jsonl(root / "cves.jsonl", [record.model_dump(mode="json") for record in cves])
    write_json(root / "capec.json", [record.model_dump(mode="json") for record in capecs])
    write_jsonl(
        root / "cve_capec_candidates.jsonl",
        [
            {
                "cve_id": "CVE-2024-0001",
                "cwe_id": "CWE-89",
                "candidate_capec_ids": ["CAPEC-66", "CAPEC-100", "CAPEC-126"],
            },
            {
                "cve_id": "CVE-2024-0001",
                "cwe_id": "CWE-89",
                "candidate_capec_ids": ["CAPEC-66", "CAPEC-999"],
            },
            {
                "cve_id": "CVE-2024-0002",
                "cwe_id": "CWE-120",
                "candidate_capec_ids": ["CAPEC-100", "CAPEC-126"],
            },
            {
                "cve_id": "CVE-2024-0003",
                "cwe_id": "CWE-22",
                "candidate_capec_ids": ["CAPEC-126", "CAPEC-66"],
            },
        ],
    )
    write_jsonl(
        root / "cve2capec_reference.jsonl",
        [
            {"cve_id": "CVE-2024-0001", "capec_ids": ["CAPEC-66"]},
            {"cve_id": "CVE-2024-0002", "capec_ids": ["CAPEC-100"]},
            {"cve_id": "CVE-2024-0003", "capec_ids": ["CAPEC-126"]},
        ],
    )
    write_json(
        root / "splits.json",
        {
            "train": [],
            "validation": [],
            "capec_eval_100": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "human_eval_20": [],
        },
    )
    return root


def test_dataset_loader_unions_candidates_and_drops_unknown_capec(tmp_path: Path):
    dataset = load_selection_dataset(_build_dataset(tmp_path))

    assert dataset.candidates["CVE-2024-0001"] == ("CAPEC-100", "CAPEC-126", "CAPEC-66")
    assert "CAPEC-999" not in dataset.candidates["CVE-2024-0001"]
    assert dataset.references["CVE-2024-0001"] == frozenset({"CAPEC-66"})


def test_tfidf_selector_picks_expected_capec(tmp_path: Path):
    dataset = load_selection_dataset(_build_dataset(tmp_path))
    selector = TfidfCapecSelector(
        dataset.capecs,
        background_texts=[record.description for record in dataset.cves.values()],
    )

    predictions, metrics = evaluate_selector(selector, dataset, "capec_eval_100")

    assert [prediction.selected_capec_id for prediction in predictions] == [
        "CAPEC-66",
        "CAPEC-100",
        "CAPEC-126",
    ]
    assert metrics.correct == 3
    assert metrics.accuracy == 1.0
    assert metrics.candidate_recall == 1.0


def test_word2vec_selector_returns_candidates(tmp_path: Path):
    pytest.importorskip("gensim")
    dataset = load_selection_dataset(_build_dataset(tmp_path))
    selector = Word2VecCapecSelector(
        dataset.capecs,
        background_texts=[record.description for record in dataset.cves.values()],
        vector_size=20,
        window=3,
        epochs=30,
        workers=1,
    )

    predictions, metrics = evaluate_selector(selector, dataset, "capec_eval_100")

    assert metrics.cves == 3
    assert metrics.method == "word2vec"
    assert all(prediction.selected_capec_id for prediction in predictions)
    assert all(prediction.score >= 0.0 for prediction in predictions)
