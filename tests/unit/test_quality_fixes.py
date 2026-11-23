"""Small quality fixes: help, Markdown escaping, API config lifecycle."""

import json
from pathlib import Path

import pytest

from vuln2action.cli import main as cli_main
from vuln2action.evidence import save_report


def test_cli_help_labels_llm_as_stub(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "llm (stub)" in out
    assert "reproduction" not in out.lower()


def test_report_md_escapes_adversarial_values(tmp_path):
    payload = {
        "cve_id": "CVE|`x`<y>\nnext",
        "provider": "provider`x`|y",
        "result": {"status": "SIMULATED"},
        "evidence": {},
    }
    paths = save_report("run|`x`", payload, output_dir=tmp_path)
    text = Path(paths.markdown_path).read_text(encoding="utf-8")
    assert "\\|" in text
    assert "\\`" in text
    assert "&lt;y&gt;" in text
    assert "next" in text.splitlines()[2]
    report = json.loads(Path(paths.json_path).read_text(encoding="utf-8"))
    assert report["cve_id"] == "CVE|`x`<y>\nnext"


def test_api_loads_settings_once_at_app_creation(monkeypatch):
    pytest.importorskip("fastapi")
    import api.main as api_main
    from vuln2action import config

    calls = []
    real = config.load_settings

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(config, "load_settings", counting)
    app = api_main.create_app()
    assert len(calls) == 1
    assert app.state.settings is not None
    assert len(calls) == 1
