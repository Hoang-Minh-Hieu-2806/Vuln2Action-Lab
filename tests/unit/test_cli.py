"""CLI contract tests."""

import json

from vuln2action.cli import main


def test_json_only_output_is_machine_readable(capsys):
    exit_code = main(["--sample", "CVE-2024-0001", "--json-only"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["result"]["status"] == "SIMULATED"
