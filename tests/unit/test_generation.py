"""Unit tests for the generation abstraction (provider-swappable)."""
import pytest

from src.generation import GenerationProvider, RuleBasedGenerator, get_generator
from src.generation.parser import parse_workflow
from src.ingestion.cve import get_sample_cve
from src.retrieval.ranker import build_contexts_for_cve


def test_rule_based_generates_valid_workflow():
    cve = get_sample_cve("CVE-2024-0002")
    wf = RuleBasedGenerator().generate(cve, build_contexts_for_cve(cve))
    assert parse_workflow(wf)["cve_id"] == "CVE-2024-0002"
    assert len(wf["steps"]) >= 3


def test_factory_returns_interface_and_unknown_raises():
    assert isinstance(get_generator("rule_based"), GenerationProvider)
    with pytest.raises(ValueError):
        get_generator("nope")


def test_llm_t5_stubs_raise_helpful_errors():
    cve = get_sample_cve("CVE-2024-0001")
    with pytest.raises(NotImplementedError):
        get_generator("llm").generate(cve, [])
    with pytest.raises(NotImplementedError):
        get_generator("t5").generate(cve, [])
