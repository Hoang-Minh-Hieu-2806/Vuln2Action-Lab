"""End-to-end offline pipeline contract."""

from pathlib import Path

from vuln2action.config import load_settings
from vuln2action.connectors import load_sample_cves
from vuln2action.domain import ReproductionStatus
from vuln2action.evidence import save_report
from vuln2action.pipeline import run_pipeline


def test_pipeline_runs_for_every_sample():
    settings = load_settings()
    for cve in load_sample_cves():
        outcome = run_pipeline(cve, settings=settings, provider="rule_based")
        assert outcome.result.status is ReproductionStatus.SIMULATED
        assert outcome.workflow.cve_id == cve.cve_id


def test_report_writer(tmp_path):
    cve = load_sample_cves()[0]
    payload = run_pipeline(cve, settings=load_settings()).to_dict()
    paths = save_report("test-run", payload, output_dir=tmp_path)
    assert Path(paths.json_path).name == "report.json"
    assert Path(paths.json_path).parent.name == "test-run"
