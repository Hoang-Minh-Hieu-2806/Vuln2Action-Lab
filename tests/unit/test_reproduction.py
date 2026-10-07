"""Unit tests for planner/executor/validator + safety guard."""
import pytest

from src.reproduction.executor import ReproductionExecutor, is_allowed_target
from src.reproduction.planner import ReproductionPlanner
from src.reproduction.validator import Validator


def test_allowed_hosts_guard():
    assert is_allowed_target("localhost")
    assert is_allowed_target("127.0.0.1")
    assert not is_allowed_target("example.com")
    with pytest.raises(ValueError):
        ReproductionExecutor().execute([{"id": "x", "action": "a", "target": "example.com"}])


def test_plan_execute_validate_passes():
    wf = {"cve_id": "CVE-2024-0001", "lab_id": "cve-001",
          "steps": [{"id": "s1", "action": "probe", "detail": "d"}]}
    plan = ReproductionPlanner().plan(wf, lab_id="cve-001")
    info = ReproductionExecutor(simulate=True).execute(plan)
    res = Validator().validate("CVE-2024-0001", "cve-001", info)
    assert res.status.value == "PASS"
    assert res.steps_executed == 1
