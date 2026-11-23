"""Provider selection has one source of truth: the requested provider name."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from vuln2action.config import ApplicationSettings, T5ProviderSettings, load_model_settings
from vuln2action.domain import CveRecord
from vuln2action.generation import get_generator

REPO = Path(__file__).resolve().parents[2]


def test_tracked_model_settings_load_without_enabled_flags():
    settings = load_model_settings()
    assert settings.providers.rule_based == {}
    assert "enabled" not in settings.providers.llm
    assert settings.providers.t5.base_checkpoint == "t5-small"
    assert "enabled" not in T5ProviderSettings.model_fields


def test_unknown_enabled_flag_is_rejected():
    with pytest.raises(ValidationError):
        ApplicationSettings.model_validate({"generation": {"providers": {"t5": {"enabled": True}}}})


@pytest.mark.parametrize(
    ("name", "expected"),
    [("rule_based", "rule_based"), ("t5", "t5"), ("llm", "llm")],
)
def test_provider_selection(name, expected):
    assert get_generator(name).name == expected


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError, match="Unknown generator provider"):
        get_generator("magic")


def test_llm_provider_remains_a_stub():
    cve = CveRecord(cve_id="CVE-1", description="demo")
    with pytest.raises(NotImplementedError, match="LLM provider"):
        get_generator("llm").generate(cve, [])


def test_default_provider_is_rule_based():
    assert get_generator(None).name == "rule_based"


def test_legacy_enabled_flag_gets_actionable_error(tmp_path):
    config = tmp_path / "models.yaml"
    config.write_text("providers:\n  t5:\n    enabled: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="legacy 'enabled' provider flags"):
        load_model_settings(config)
