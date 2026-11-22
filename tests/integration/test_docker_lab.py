"""Live Docker lab integration (opt-in).

Run with::

    V2A_DOCKER_TESTS=1 python -m pytest tests/integration/test_docker_lab.py -v

This test builds and runs ``labs/cve-001`` on localhost, so it is skipped by
default in CI. It asserts a real PASS from the checked-in counterfactual.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from vuln2action.config import load_settings
from vuln2action.connectors import get_sample_cve, load_lab_manifest
from vuln2action.domain import ReproductionStatus
from vuln2action.generation import RuleBasedGenerator
from vuln2action.pipeline import run_pipeline
from vuln2action.reproduction import ReproductionExecutor, ReproductionPlanner, Validator

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


def test_live_lab_evidence_schema():
    outcome = run_pipeline(
        get_sample_cve("CVE-2024-0001"),
        settings=load_settings(),
        simulate=False,
    )
    evidence = outcome.evidence
    assert evidence.generation is not None
    assert evidence.generation["input"]["cve_id"] == "CVE-2024-0001"
    assert evidence.workflow == outcome.workflow.model_dump(mode="json")
    assert evidence.plan["lab_id"] == "cve-001"
    assert evidence.checkpoint_id is None
    assert evidence.validation_result["status"] == "PASS"


def test_live_lab_uses_allowlisted_action_only():
    outcome = run_pipeline(
        get_sample_cve("CVE-2024-0001"),
        settings=load_settings(),
        simulate=False,
    )
    log = outcome.execution.log
    assert any(
        line.startswith("[workflow] step ") and "selected allowlisted action" in line
        for line in log
    )
    assert any(
        line.startswith("[validate] ") and "validation/labctl.py validate" in line for line in log
    )
    joined = "\n".join(log)
    for step in outcome.workflow.steps:
        assert step.detail not in joined


def test_live_lab_teardown_removes_containers():
    run_pipeline(
        get_sample_cve("CVE-2024-0001"),
        settings=load_settings(),
        simulate=False,
    )
    probe = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            "name=vuln2action-cve-001",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode == 0
    assert probe.stdout.strip() == ""


def test_broken_patched_counterfactual_is_not_pass(tmp_path: Path):
    source = Path(__file__).resolve().parents[2] / "labs" / "cve-001"
    lab_dir = tmp_path / "cve-001"
    shutil.copytree(source, lab_dir)
    app_path = lab_dir / "target" / "app.py"
    original = 'html.escape(query) if MODE == "patched" else query'
    text = app_path.read_text(encoding="utf-8")
    assert original in text
    app_path.write_text(text.replace(original, "query"), encoding="utf-8")

    cve = get_sample_cve("CVE-2024-0001")
    workflow = RuleBasedGenerator().generate(cve, [])
    plan = ReproductionPlanner().plan(workflow, lab_id="cve-001")
    executor = ReproductionExecutor(
        simulate=False,
        labs_root=tmp_path,
        allowed_hosts={"localhost", "127.0.0.1"},
        timeout_seconds=600,
    )
    try:
        execution = executor.execute(plan, manifest=load_lab_manifest("cve-001"))
        result = Validator().validate(cve.cve_id, "cve-001", execution)
        assert result.status is ReproductionStatus.FAIL
        checks = result.evidence["validation"]["checks"]
        assert checks["vulnerable_reflects_unescaped"] is True
        assert checks["patched_reflects_escaped"] is False
    finally:
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(lab_dir / "docker-compose.yml"),
                "down",
                "--remove-orphans",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
