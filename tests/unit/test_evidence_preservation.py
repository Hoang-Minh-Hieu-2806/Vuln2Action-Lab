"""Evidence preservation: atomic writes, no silent overwrite, safe clean."""

import json
from pathlib import Path

import pytest

from vuln2action.evidence import save_report
from vuln2action.evidence.provenance import read_provenance
from vuln2action.utils.filesystem import write_json

REPO = Path(__file__).resolve().parents[2]
PAYLOAD = {"cve_id": "CVE-1", "result": {"status": "SIMULATED"}, "evidence": {}}


def test_write_json_creates_parent_and_parses(tmp_path):
    path = tmp_path / "nested" / "report.json"
    returned = write_json(path, {"text": "đồ án"})
    assert returned == path
    assert json.loads(path.read_text(encoding="utf-8")) == {"text": "đồ án"}


def test_write_json_serialization_failure_cleans_temp(tmp_path):
    path = tmp_path / "report.json"
    with pytest.raises(TypeError):
        write_json(path, {"bad": object()})
    assert not path.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_json_replace_failure_keeps_existing_file(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text('{"old": true}', encoding="utf-8")

    def fail(*args, **kwargs):
        raise OSError("replace failed")

    monkeypatch.setattr("vuln2action.utils.filesystem.os.replace", fail)
    with pytest.raises(OSError):
        write_json(path, {"new": True})
    assert json.loads(path.read_text(encoding="utf-8")) == {"old": True}
    assert list(tmp_path.glob("*.tmp")) == []


def test_same_run_id_does_not_overwrite(tmp_path):
    first = save_report("demo", PAYLOAD, output_dir=tmp_path)
    original = Path(first.json_path).read_text(encoding="utf-8")
    with pytest.raises(FileExistsError, match="already exists"):
        save_report("demo", {**PAYLOAD, "cve_id": "CVE-2"}, output_dir=tmp_path)
    assert Path(first.json_path).read_text(encoding="utf-8") == original


def test_explicit_overwrite_is_opt_in(tmp_path):
    save_report("demo", PAYLOAD, output_dir=tmp_path)
    second = save_report(
        "demo", {**PAYLOAD, "cve_id": "CVE-2"}, output_dir=tmp_path, overwrite=True
    )
    assert json.loads(Path(second.json_path).read_text(encoding="utf-8"))["cve_id"] == "CVE-2"


def test_provenance_sidecar_still_readable(tmp_path):
    paths = save_report("demo", PAYLOAD, output_dir=tmp_path)
    report = json.loads(Path(paths.json_path).read_text(encoding="utf-8"))
    document = read_provenance(Path(paths.run_dir), report)
    assert document is not None
    assert document.integrity is not None


def test_make_clean_does_not_touch_research_data():
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    clean = makefile.split("clean:", 1)[1].split("docker-up:", 1)[0]
    for unsafe in ("results/", "artifacts/", "reports/"):
        assert unsafe not in clean
    assert "__pycache__" in clean
    assert ".pytest_cache" in clean
