"""CLI contract tests."""

import io
import json
import sys
from types import SimpleNamespace

from vuln2action.cli import main


def test_json_only_output_is_machine_readable(capsys):
    exit_code = main(["--sample", "CVE-2024-0001", "--json-only"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["result"]["status"] == "SIMULATED"


def test_save_prints_non_ascii_path_without_encoding_error(monkeypatch):
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(
        "vuln2action.cli.save_report",
        lambda *args, **kwargs: SimpleNamespace(run_dir="C:/temp/đồ án/run"),
    )
    exit_code = main(["--sample", "CVE-2024-0001", "--save", "demo"])
    assert exit_code == 0
    assert "run" in stream.buffer.getvalue().decode("utf-8")
