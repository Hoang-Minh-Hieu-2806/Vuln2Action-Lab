"""End-to-end smoke test: sample CVE -> pipeline -> PASS + report payload."""
from src.evidence.reporter import save_report
from src.ingestion.cve import load_sample_cves
from src.pipeline.pipeline import run_pipeline
from src.utils.config import load_settings


def test_pipeline_runs_for_every_sample(tmp_path):
    settings = load_settings()
    assert "pipeline" in settings
    for cve in load_sample_cves():
        out = run_pipeline(cve, provider="rule_based")
        d = out.to_dict()
        assert d["result"]["status"] == "PASS"
        assert d["workflow"]["cve_id"] == cve.cve_id


def test_report_writer(tmp_path):
    cve = load_sample_cves()[0]
    payload = run_pipeline(cve).to_dict()
    paths = save_report("test-run", payload, output_dir=tmp_path)
    assert paths.json_path.endswith(".json")
