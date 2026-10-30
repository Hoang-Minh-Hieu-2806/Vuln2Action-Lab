"""Leakage audit and the generation evaluation harness.

The audit is the most important part of P1.2: metrics computed over leaked cases
are not evidence. These tests pin the detection rules and the split reporting,
using tiny synthetic flows so nothing depends on the trained checkpoint.
"""

import json

import pytest

from evaluation.generation import evaluate_generation as harness
from evaluation.generation.evaluate_generation import (
    FlowCase,
    FlowDataset,
    audit_leakage,
    evaluate_system,
    load_flow_dataset,
    system_metadata,
)
from evaluation.generation.evaluate_generation import (
    main as evaluate_main,
)

FLOW_A = (
    "CAPEC-1 Alpha\n1. Explore: survey the application for inputs\n"
    "2. Experiment: probe with quotes\n3. Exploit: extract data"
)
FLOW_B = (
    "CAPEC-2 Beta\n1. Explore: enumerate services on the host\n"
    "2. Experiment: send malformed requests\n3. Exploit: crash the process"
)
# Nearly identical to FLOW_A on purpose (sibling-pattern style duplication).
FLOW_A_NEAR = (
    "CAPEC-3 Gamma\n1. Explore: survey the application for inputs\n"
    "2. Experiment: probe with quote characters\n3. Exploit: extract the data"
)


def _case(case_id: str, flow: str, name: str = "") -> FlowCase:
    return FlowCase(
        capec_id=case_id,
        name=name or case_id,
        cwe_ids=["CWE-89"],
        input_text=f"Generate a flow for {case_id}",
        target_flow=flow,
    )


class _FixedGenerator:
    """Emits a fixed string, so harness behaviour is testable without a model."""

    def __init__(self, text: str) -> None:
        self.text = text

    def generate(self, cve, contexts):
        from vuln2action.domain import Workflow, WorkflowStep

        return Workflow(
            cve_id=cve.cve_id,
            provider="fixed",
            steps=[WorkflowStep(id="explore-1", action="Explore step", detail=self.text)],
        )


def test_audit_detects_no_leakage_for_distinct_flows():
    result = audit_leakage([_case("CAPEC-1", FLOW_A)], [_case("CAPEC-2", FLOW_B)])
    assert result["near_duplicates"] == []
    assert result["exact_duplicate_targets"] == []
    assert result["clean_validation_count"] == 1
    assert "no leakage" in result["verdict"]


def test_audit_detects_near_duplicate_flows():
    result = audit_leakage([_case("CAPEC-1", FLOW_A)], [_case("CAPEC-3", FLOW_A_NEAR)])
    assert result["near_duplicates"], "near-identical prose must be flagged"
    assert result["near_duplicates"][0]["validation_case"] == "CAPEC-3"
    assert result["near_duplicates"][0]["train_case"] == "CAPEC-1"
    assert result["near_duplicates"][0]["similarity"] >= harness.NEAR_DUPLICATE_THRESHOLD
    assert result["clean_validation_count"] == 0


def test_audit_detects_exact_duplicates():
    result = audit_leakage([_case("CAPEC-1", FLOW_A)], [_case("CAPEC-9", FLOW_A)])
    assert result["exact_duplicate_targets"] == ["CAPEC-9"]


def test_audit_detects_capec_id_overlap():
    result = audit_leakage([_case("CAPEC-1", FLOW_A)], [_case("CAPEC-1", FLOW_B)])
    assert result["capec_id_overlap"] == ["CAPEC-1"]


def test_audit_reports_cwe_relation_for_flagged_pairs():
    result = audit_leakage([_case("CAPEC-1", FLOW_A)], [_case("CAPEC-3", FLOW_A_NEAR)])
    assert result["near_duplicates"][0]["shares_cwe"] is True


def test_leakage_clean_subset_excludes_flagged_cases():
    train = [_case("CAPEC-1", FLOW_A)]
    validation = [_case("CAPEC-3", FLOW_A_NEAR), _case("CAPEC-2", FLOW_B)]
    result = audit_leakage(train, validation)
    assert result["leaked_validation_cases"] == ["CAPEC-3"]
    assert result["clean_validation_cases"] == ["CAPEC-2"]


def test_evaluate_system_separates_clean_and_all():
    train = [_case("CAPEC-1", FLOW_A)]
    validation = [_case("CAPEC-3", FLOW_A_NEAR), _case("CAPEC-2", FLOW_B)]
    leakage = audit_leakage(train, validation)
    clean = set(leakage["clean_validation_cases"])

    generator = _FixedGenerator("1. Explore: survey 2. Experiment: probe 3. Exploit: extract")
    result = evaluate_system(
        "fixed",
        validation,
        generator,
        metadata=system_metadata("fixed", checkpoint="test", fine_tuned=False),
        leakage_clean=clean,
    )
    assert result["cases"] == 2
    assert result["leakage_clean"]["cases"] == 1
    assert result["mean"]["output_validity"] == 1.0
    assert len(result["rows"]) == 2


def test_evaluate_system_records_failures():
    validation = [_case("CAPEC-2", FLOW_B)]
    generator = _FixedGenerator("nothing useful")
    result = evaluate_system(
        "fixed",
        validation,
        generator,
        metadata=system_metadata("fixed", checkpoint="test", fine_tuned=False),
        leakage_clean={"CAPEC-2"},
        failure_limit=1,
    )
    failure = result["failures"][0]
    assert failure["case_id"] == "CAPEC-2"
    # The fixed generator's step id is "explore-1", so Explore is present and the
    # remaining two phases are the ones actually missing.
    assert failure["missing_phase_names"] == ["Experiment", "Exploit"]
    assert result["mean"]["output_validity"] == 0.0


def test_phase_breakdown_has_all_three_phases():
    validation = [_case("CAPEC-2", FLOW_B)]
    result = evaluate_system(
        "fixed",
        validation,
        _FixedGenerator("1. Explore: enumerate services on the host"),
        metadata=system_metadata("fixed", checkpoint="test", fine_tuned=False),
        leakage_clean={"CAPEC-2"},
    )
    assert set(result["phase_breakdown"]) == {"Explore", "Experiment", "Exploit"}
    assert result["phase_breakdown"]["Explore"]["cases"] == 1


def test_metadata_never_claims_fine_tuning_for_a_base_model():
    metadata = system_metadata("flan-t5", checkpoint="google/flan-t5-small", fine_tuned=False)
    assert metadata["fine_tuned"] is False
    assert metadata["kind"] == "baseline"
    assert "not fine-tuned" in metadata["note"]


def test_metadata_reports_fine_tuned_when_requested():
    metadata = system_metadata("t5", checkpoint="models/x", fine_tuned=True, base="t5-small")
    assert metadata["fine_tuned"] is True
    assert metadata["kind"] == "fine-tuned"


def test_fine_tuned_detection_requires_a_training_summary(tmp_path):
    assert harness._fine_tuned_checkpoint(str(tmp_path)) is False
    (tmp_path / "training_summary.json").write_text("{}", encoding="utf-8")
    assert harness._fine_tuned_checkpoint(str(tmp_path)) is True


def test_load_dataset_reports_missing_file(tmp_path):
    with pytest.raises(harness.DatasetMissingError, match="build_t5_dataset"):
        load_flow_dataset(tmp_path / "absent.json")


def _write_dataset(tmp_path, train, validation):
    payload = {
        "version": "test",
        "provenance": {"source_kind": "unit test"},
        "limitations": ["synthetic"],
        "seed": 13,
        "validation_fraction": 0.5,
        "train": [case.model_dump() for case in train],
        "validation": [case.model_dump() for case in validation],
    }
    path = tmp_path / "flows.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_dataset_validation_round_trip(tmp_path):
    path = _write_dataset(tmp_path, [_case("CAPEC-1", FLOW_A)], [_case("CAPEC-2", FLOW_B)])
    dataset = load_flow_dataset(path)
    assert isinstance(dataset, FlowDataset)
    assert len(dataset.train) == 1
    assert dataset.train[0].capec_id == "CAPEC-1"


def test_cli_writes_json_csv_and_markdown(tmp_path):
    path = _write_dataset(tmp_path, [_case("CAPEC-1", FLOW_A)], [_case("CAPEC-2", FLOW_B)])
    out_dir = tmp_path / "out"
    code = evaluate_main(
        [
            "--dataset",
            str(path),
            "--systems",
            "rule_based",
            "--save",
            str(out_dir),
        ]
    )
    assert code == 0
    run_dirs = list(out_dir.glob("generation_*"))
    assert len(run_dirs) == 1
    report = json.loads((run_dirs[0] / "report.json").read_text(encoding="utf-8"))
    assert "rule_based" in report["systems"]
    assert "leakage" in report
    assert (run_dirs[0] / "per_case.csv").is_file()
    assert (run_dirs[0] / "report.md").is_file()
    assert (run_dirs[0] / "leakage.json").is_file()


def test_cli_rejects_unknown_system(tmp_path):
    path = _write_dataset(tmp_path, [_case("CAPEC-1", FLOW_A)], [_case("CAPEC-2", FLOW_B)])
    with pytest.raises(SystemExit):
        evaluate_main(["--dataset", str(path), "--systems", "nope"])
