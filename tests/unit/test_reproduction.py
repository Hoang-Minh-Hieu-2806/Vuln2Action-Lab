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
    assert not is_allowed_target("example.com")


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
