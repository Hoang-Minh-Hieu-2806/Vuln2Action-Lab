"""Regression tests for strict cross-stage contracts."""

import pytest
from pydantic import ValidationError

from vuln2action.config import ApplicationSettings
from vuln2action.domain import Workflow
from vuln2action.generation.parser import parse_workflow


def test_unknown_settings_are_rejected():
    with pytest.raises(ValidationError):
        ApplicationSettings.model_validate({"pipeline": {"surprise": True}})


def test_workflow_rejects_empty_steps():
    with pytest.raises(ValidationError):
        Workflow(cve_id="DEMO-1", provider="test", steps=[])


def test_parser_rejects_non_json_text():
    with pytest.raises(ValueError, match="valid JSON"):
        parse_workflow("this is not json")
