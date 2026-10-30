"""Generation contracts and provider swapping."""

import pytest

from vuln2action.connectors import get_sample_cve
from vuln2action.generation import GenerationProvider, RuleBasedGenerator, get_generator
from vuln2action.generation.parser import parse_workflow
from vuln2action.retrieval.ranker import build_contexts_for_cve


def test_rule_based_generates_valid_workflow():
    cve = get_sample_cve("CVE-2024-0002")
    workflow = RuleBasedGenerator().generate(cve, build_contexts_for_cve(cve))
    assert parse_workflow(workflow).cve_id == "CVE-2024-0002"
    assert len(workflow.steps) >= 3


def test_factory_returns_interface_and_unknown_raises():
    assert isinstance(get_generator("rule_based"), GenerationProvider)
    with pytest.raises(ValueError):
        get_generator("nope")


def test_llm_stub_raises_helpful_error():
    """The LLM provider is still a stub; T5 is real and covered in test_generation_t5."""
    cve = get_sample_cve("CVE-2024-0001")
    with pytest.raises(NotImplementedError):
        get_generator("llm").generate(cve, [])
