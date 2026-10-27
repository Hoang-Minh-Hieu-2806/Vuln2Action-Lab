"""Live Docker lab integration (opt-in).

Run with::

    V2A_DOCKER_TESTS=1 python -m pytest tests/integration/test_docker_lab.py -v

This test builds and runs ``labs/cve-001`` on localhost, so it is skipped by
default in CI. It asserts a real PASS from the checked-in counterfactual.
"""

import os

import pytest

from vuln2action.config import load_settings
from vuln2action.connectors import get_sample_cve
from vuln2action.domain import ReproductionStatus
from vuln2action.pipeline import run_pipeline

pytestmark = pytest.mark.skipif(
    os.environ.get("V2A_DOCKER_TESTS") != "1",
    reason="set V2A_DOCKER_TESTS=1 to run the isolated Docker lab test",
)


def test_live_lab_produces_a_real_pass():
    outcome = run_pipeline(
        get_sample_cve("CVE-2024-0001"),
        settings=load_settings(),
        simulate=False,
    )
    assert outcome.execution.simulated is False
    assert outcome.result.status is ReproductionStatus.PASS
    assert outcome.evidence.validation_result is not None
    assert outcome.evidence.validation_result["status"] == "PASS"


def test_live_lab_teardown_leaves_no_containers():
    # run once more to ensure up/down is idempotent
    outcome = run_pipeline(
        get_sample_cve("CVE-2024-0001"),
        settings=load_settings(),
        simulate=False,
    )
    assert outcome.result.status is ReproductionStatus.PASS
