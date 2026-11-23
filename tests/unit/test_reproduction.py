"""Planning, target guarding, and truthful simulation status."""

import pytest

from vuln2action.domain import ReproductionStatus, Workflow, WorkflowStep
from vuln2action.reproduction import (
    ReproductionExecutor,
    ReproductionPlanner,
    Validator,
    is_allowed_target,
)


def test_allowed_hosts_guard():
    assert is_allowed_target("localhost")
    assert is_allowed_target("127.0.0.1")
    assert is_allowed_target("localhost", None)
    assert not is_allowed_target("example.com")


def test_explicit_empty_allowlist_denies_everything():
    assert not is_allowed_target("localhost", set())
    assert not is_allowed_target("127.0.0.1", [])


def test_invalid_allowlist_entries_cannot_grant_access():
    allowed = {123, "", "   ", "LOCALHOST"}
    assert is_allowed_target(" localhost ", allowed)
    assert not is_allowed_target("example.com", allowed)


def test_explicit_allowlist_is_not_widened():
    assert is_allowed_target("example.com", {"example.com"})
    assert not is_allowed_target("localhost", {"example.com"})


def test_empty_allowlist_refuses_execution_even_in_simulation():
    workflow = Workflow(
        cve_id="DEMO-1",
        provider="test",
        lab_id="demo",
        steps=[WorkflowStep(id="s1", action="probe", detail="safe")],
    )
    plan = ReproductionPlanner().plan(workflow)
    with pytest.raises(ValueError, match="Refused non-local target"):
        ReproductionExecutor(simulate=True, allowed_hosts=set()).execute(plan)


def test_non_local_plan_is_refused():
    workflow = Workflow(
        cve_id="DEMO-1",
        provider="test",
        lab_id="demo",
        steps=[WorkflowStep(id="s1", action="probe", detail="safe")],
    )
    plan = ReproductionPlanner().plan(workflow)
    plan.steps[0].target = "example.com"
    with pytest.raises(ValueError):
        ReproductionExecutor().execute(plan)


def test_simulation_never_claims_pass():
    workflow = Workflow(
        cve_id="DEMO-1",
        provider="test",
        lab_id="demo",
        steps=[WorkflowStep(id="s1", action="probe", detail="safe")],
    )
    plan = ReproductionPlanner().plan(workflow)
    execution = ReproductionExecutor(simulate=True).execute(plan)
    result = Validator().validate("DEMO-1", "demo", execution)
    assert result.status is ReproductionStatus.SIMULATED
    assert result.steps_executed == 1
