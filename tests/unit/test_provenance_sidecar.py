"""Provenance sidecar writer, reader and compatibility tests."""

import json
from pathlib import Path

import pytest

from vuln2action.domain import EvidenceBundle, Workflow
from vuln2action.evidence import save_report
from vuln2action.evidence.provenance import ProvenanceError, read_provenance


def _payload():
    return {
        "cve_id": "CVE-TEST",
        "provider": "rule_based",
        "workflow": {
            "cve_id": "CVE-TEST",
            "provider": "rule_based",
            "steps": [{"id": "lab-up", "action": "Start lab", "detail": "Start the lab."}],
            "checkpoint_id": None,
        },
        "plan": {"cve_id": "CVE-TEST", "lab_id": "cve-001", "steps": [{"id": "lab-up"}]},
        "execution": {"simulated": True},
        "result": {"status": "SIMULATED"},
        "evidence": {
            "collected_at": "2026-01-01T00:00:00+00:00",
            "checkpoint_id": None,
            "generation": {
                "provider": "rule_based",
                "input": {
                    "cve_id": "CVE-TEST",
                    "context_sources": ["CWE-79", "reference:https://example.com"],
                },
                "output": {"provider": "rule_based"},
            },
        },
    }


def _saved(tmp_path):
    paths = save_report("case", _payload(), output_dir=tmp_path)
    run_dir = Path(paths.json_path).parent
    report = json.loads(Path(paths.json_path).read_text(encoding="utf-8"))
    return run_dir, report


def test_sidecar_written_before_report(tmp_path):
    run_dir, _ = _saved(tmp_path)
    sidecar = run_dir / "provenance.json"
    assert sidecar.is_file()
    document = json.loads(sidecar.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert {"retrieval", "generation", "execution", "environment", "integrity"} <= set(document)
    assert document["generation"]["provider"] == "rule_based"
    assert document["retrieval"]["backend"] == "NOT_AVAILABLE"
    assert document["environment"]["repository_commit"] is None


def test_report_contains_valid_relative_reference(tmp_path):
    run_dir, report = _saved(tmp_path)
    reference = report["evidence"]["generation"]["provenance_ref"]
    assert reference == "provenance.json"
    assert not Path(reference).is_absolute()
    assert ".." not in Path(reference).parts
    assert read_provenance(run_dir, report).generation.provider == "rule_based"


def test_legacy_report_without_reference_is_readable(tmp_path):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps(_payload()), encoding="utf-8")
    report = json.loads(legacy.read_text(encoding="utf-8"))
    assert read_provenance(tmp_path, report) is None


def test_missing_sidecar_reports_clear_error(tmp_path):
    payload = _payload()
    payload["evidence"]["generation"]["provenance_ref"] = "provenance.json"
    with pytest.raises(ProvenanceError) as exc:
        read_provenance(tmp_path, payload)
    assert exc.value.code == "MISSING"


@pytest.mark.parametrize(
    "reference",
    [
        "../provenance.json",
        "..\\provenance.json",
        "C:\\outside\\provenance.json",
        "\\\\server\\share\\provenance.json",
    ],
)
def test_invalid_reference_is_rejected(tmp_path, reference):
    payload = _payload()
    payload["evidence"]["generation"]["provenance_ref"] = reference
    with pytest.raises(ProvenanceError) as exc:
        read_provenance(tmp_path, payload)
    assert exc.value.code == "INVALID_REF"


def test_malformed_sidecar_is_rejected(tmp_path):
    run_dir, report = _saved(tmp_path)
    (run_dir / "provenance.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ProvenanceError) as exc:
        read_provenance(run_dir, report)
    assert exc.value.code == "MALFORMED"


def test_digest_mismatch_is_rejected(tmp_path):
    run_dir, report = _saved(tmp_path)
    sidecar = run_dir / "provenance.json"
    document = json.loads(sidecar.read_text(encoding="utf-8"))
    document["generation"]["provider"] = "tampered"
    sidecar.write_text(json.dumps(document, indent=2), encoding="utf-8")
    with pytest.raises(ProvenanceError) as exc:
        read_provenance(run_dir, report)
    assert exc.value.code == "DIGEST_MISMATCH"


def test_sidecar_write_failure_does_not_publish_report(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("vuln2action.evidence.reporter.write_provenance", fail)
    with pytest.raises(ProvenanceError) as exc:
        save_report("case", _payload(), output_dir=tmp_path)
    assert exc.value.code == "WRITE_FAILED"
    assert not (tmp_path / "case" / "report.json").exists()
    assert not list((tmp_path / "case").glob(".provenance-*.tmp"))


def test_report_write_failure_keeps_orphan_sidecar(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("report disk full")

    monkeypatch.setattr("vuln2action.evidence.reporter.write_json", fail)
    with pytest.raises(RuntimeError, match="orphan sidecar"):
        save_report("case", _payload(), output_dir=tmp_path)
    assert (tmp_path / "case" / "provenance.json").is_file()
    assert not (tmp_path / "case" / "report.json").exists()


def test_generation_keys_survive_serialization(tmp_path):
    generation = _payload()["evidence"]["generation"]
    original = json.loads(json.dumps(generation))
    _, report = _saved(tmp_path)
    stored = report["evidence"]["generation"]
    for key, value in original.items():
        assert stored[key] == value
    assert stored["provenance_ref"] == "provenance.json"


def test_no_direct_fields_added_to_domain_models():
    assert "provenance_ref" not in EvidenceBundle.model_fields
    assert "provenance_ref" not in Workflow.model_fields
    bundle = EvidenceBundle.model_validate(_payload()["evidence"])
    assert "provenance_ref" not in bundle.model_dump(mode="json")


def test_legacy_shaped_payload_is_readable_after_serialization(tmp_path):
    payload = _payload()
    payload["evidence"].pop("checkpoint_id")
    payload["workflow"].pop("checkpoint_id")
    paths = save_report("legacy-shaped", payload, output_dir=tmp_path)
    report = json.loads(Path(paths.json_path).read_text(encoding="utf-8"))
    bundle = EvidenceBundle.model_validate(report["evidence"])
    workflow = Workflow.model_validate(report["workflow"])
    assert bundle.checkpoint_id is None
    assert workflow.checkpoint_id is None
    assert report["evidence"]["generation"]["provenance_ref"] == "provenance.json"
