"""Real-execution guards, validator parsing, and verdict mapping."""

import pytest

from vuln2action.domain import (
    ExecutionPlan,
    ExecutionResult,
    LabManifest,
    PlanStep,
    ReproductionStatus,
)
from vuln2action.reproduction import (
    ReproductionExecutor,
    Validator,
    parse_validation_output,
)


def _plan() -> ExecutionPlan:
    return ExecutionPlan(
        cve_id="DEMO-1",
        lab_id="demo",
        steps=[PlanStep(id="s1", action="probe", detail="safe", lab_id="demo")],
    )


def test_real_execution_requires_a_manifest():
    with pytest.raises(ValueError, match="requires a lab manifest"):
        ReproductionExecutor(simulate=False).execute(_plan())


def test_placeholder_lab_is_refused():
    manifest = LabManifest(
        lab_id="demo",
        vulnerability_id="DEMO-1",
        status="placeholder",
        validation_command=["python", "check.py"],
    )
    with pytest.raises(ValueError, match="placeholder"):
        ReproductionExecutor(simulate=False).execute(_plan(), manifest=manifest)


def test_ready_lab_without_counterfactual_is_refused():
    manifest = LabManifest(
        lab_id="demo",
        vulnerability_id="DEMO-1",
        status="ready",
        validation_command=["python", "check.py"],
        has_patched_counterfactual=False,
    )
    with pytest.raises(ValueError, match="counterfactual"):
        ReproductionExecutor(simulate=False).execute(_plan(), manifest=manifest)


def test_parse_validation_output_uses_last_payload():
    stdout = (
        "starting\n"
        'V2A_VALIDATION_JSON:{"status": "FAIL"}\n'
        'noise\nV2A_VALIDATION_JSON:{"status": "PASS", "checks": {"ok": true}}\n'
    )
    payload = parse_validation_output(stdout)
    assert payload is not None
    assert payload["status"] == "PASS"


def test_parse_validation_output_rejects_missing_or_bad_payload():
    assert parse_validation_output("no marker here") is None
    assert parse_validation_output("V2A_VALIDATION_JSON:not-json") is None


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        ("PASS", ReproductionStatus.PASS),
        ("FAIL", ReproductionStatus.FAIL),
        ("ERROR", ReproductionStatus.ERROR),
    ],
)
def test_validator_maps_lab_verdict(verdict: str, expected: ReproductionStatus):
    execution = ExecutionResult(
        simulated=False,
        completed=verdict in {"PASS", "FAIL"},
        steps_executed=3,
        validation={"status": verdict, "checks": {}},
    )
    result = Validator().validate("DEMO-1", "demo", execution)
    assert result.status is expected


def test_validator_skips_when_no_verdict_is_present():
    execution = ExecutionResult(simulated=False, completed=False, steps_executed=1)
    result = Validator().validate("DEMO-1", "demo", execution)
    assert result.status is ReproductionStatus.SKIPPED
