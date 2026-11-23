"""Evaluation runner accepts only implemented stages."""

import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "run_evaluation.py"
_SPEC = importlib.util.spec_from_file_location("run_evaluation_under_test", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
main = _MODULE.main

SUPPORTED = ("retrieval", "capec", "capec-independent", "generation")


@pytest.mark.parametrize("stage", SUPPORTED)
def test_supported_stage_help_exits_zero(stage, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--stage", stage, "--help"])
    assert exc.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_reproduction_stage_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--stage", "reproduction"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "invalid choice" in captured.err
    assert "reproduction" in captured.err


def test_unknown_stage_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--stage", "not-a-stage"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
