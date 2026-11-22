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
    select_validation_command,
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


def _allowlist_manifest() -> LabManifest:
    return LabManifest(
        lab_id="demo",
        vulnerability_id="DEMO-1",
        status="ready",
        validation_command=["python", "fallback.py"],
        has_patched_counterfactual=True,
        actions={
            "probe": ["python", "probe.py"],
            "validate": ["python", "validate.py"],
        },
    )


def test_workflow_step_selects_allowlisted_command():
    plan = ExecutionPlan(
        cve_id="DEMO-1",
        lab_id="demo",
        steps=[
            PlanStep(id="s1", action="Start isolated lab", detail="demo", lab_id="demo"),
            PlanStep(
                id="s2", action="Inspect target service", detail="localhost only", lab_id="demo"
            ),
            PlanStep(id="s3", action="Run lab validator", detail="demo", lab_id="demo"),
        ],
    )
    selected = select_validation_command(plan, _allowlist_manifest())
    assert selected == ("s2", "probe", ["python", "probe.py"])


def test_unmatched_workflow_falls_back_to_manifest_validation():
    plan = ExecutionPlan(
        cve_id="DEMO-1",
        lab_id="demo",
        steps=[PlanStep(id="s1", action="Start isolated lab", detail="demo", lab_id="demo")],
    )
    assert select_validation_command(plan, _allowlist_manifest()) == (
        "",
        "validation_command",
        ["python", "fallback.py"],
    )


def test_executor_refuses_non_local_target_before_running(monkeypatch):
    plan = ExecutionPlan(
        cve_id="DEMO-1",
        lab_id="demo",
        steps=[
            PlanStep(
                id="s1",
                action="probe",
                detail="safe",
                target="https://example.com",
                lab_id="demo",
            )
        ],
    )
    calls: list[object] = []
    monkeypatch.setattr(
        "vuln2action.reproduction.executor.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    with pytest.raises(ValueError, match="non-local"):
        ReproductionExecutor(
            simulate=False,
            allowed_hosts={"localhost", "127.0.0.1"},
        ).execute(plan)
    assert calls == []


def test_generated_text_never_becomes_a_command():
    plan = ExecutionPlan(
        cve_id="DEMO-1",
        lab_id="demo",
        steps=[
            PlanStep(
                id="s1",
                action="Probe",
                detail="rm -rf /; python -c 'import os'",
                lab_id="demo",
            )
        ],
    )
    _, _, command = select_validation_command(plan, _allowlist_manifest())
    assert command == ["python", "probe.py"]
