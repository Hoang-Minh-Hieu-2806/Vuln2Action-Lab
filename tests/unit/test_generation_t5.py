"""T5 generation: parsing, workflow shaping, config, and graceful degradation.

These tests never download a checkpoint. Model behaviour is exercised with a fake
tokenizer/model so the suite stays offline and fast; the optional stack is
import-skipped where it is genuinely needed.
"""

import pytest

from vuln2action.config import T5ProviderSettings, load_model_settings
from vuln2action.connectors import get_sample_cve
from vuln2action.domain import CveRecord, RetrievedContext
from vuln2action.generation import GenerationProvider, RuleBasedGenerator, get_generator
from vuln2action.generation.parser import parse_workflow
from vuln2action.generation.t5 import (
    T5Generator,
    T5UnavailableError,
    build_model_input,
    flow_to_workflow,
    parse_flow,
)
from vuln2action.retrieval.ranker import build_contexts_for_cve

EXPECTED = (
    "CAPEC-66 SQL Injection\n"
    "1. Explore: [Survey the application] Map every parameter that reaches a query.\n"
    "   - Use a proxy to record requests.\n"
    "2. Experiment: [Probe for injection] Submit quote characters and watch for errors.\n"
    "3. Exploit: [Extract data] Use a tautology to bypass the login check.\n"
)


def test_parse_flow_reads_numbered_phases():
    steps = parse_flow(EXPECTED)
    assert [step["phase"] for step in steps] == ["Explore", "Experiment", "Exploit"]
    assert "Survey the application" in steps[0]["description"]
    assert "tautology" in steps[2]["description"]


def test_parse_flow_handles_single_line_output():
    """Small checkpoints often drop newlines; steps must still be recovered."""
    flat = "CAPEC-66 SQL Injection 1. Explore: map inputs 2. Experiment: probe 3. Exploit: extract"
    steps = parse_flow(flat)
    assert [step["phase"] for step in steps] == ["Explore", "Experiment", "Exploit"]
    assert steps[0]["description"] == "map inputs"


def test_parse_flow_tolerates_missing_indices():
    steps = parse_flow("Explore: map inputs Experiment: probe Exploit: extract")
    assert [step["phase"] for step in steps] == ["Explore", "Experiment", "Exploit"]


def test_parse_flow_returns_empty_for_unstructured_text():
    assert parse_flow("the model rambled without any phase marker") == []
    assert parse_flow("") == []


def test_flow_to_workflow_produces_valid_steps():
    cve = get_sample_cve("CVE-2024-0002")
    workflow = flow_to_workflow(EXPECTED, cve, [])
    parsed = parse_workflow(workflow)
    assert parsed.cve_id == "CVE-2024-0002"
    assert parsed.provider == "t5"
    assert len(parsed.steps) == 3
    assert [step.id.split("-")[0] for step in parsed.steps] == [
        "explore",
        "experiment",
        "exploit",
    ]
    assert "not a validated exploit" in parsed.safety


def test_flow_to_workflow_preserves_unparseable_output():
    """A malformed generation must not silently vanish."""
    cve = get_sample_cve("CVE-2024-0001")
    workflow = flow_to_workflow("garbage output", cve, [])
    assert len(workflow.steps) == 1
    assert workflow.steps[0].id == "review"
    assert "garbage" in workflow.steps[0].detail


def test_flow_to_workflow_keeps_technique_text():
    """Technique bullets fall inside the step body and must not be dropped."""
    cve = get_sample_cve("CVE-2024-0002")
    workflow = flow_to_workflow(EXPECTED, cve, [])
    assert "Use a proxy to record requests" in workflow.steps[0].detail


def test_build_model_input_mentions_cwe_and_capec():
    cve = CveRecord(cve_id="CVE-2024-9999", description="SQL injection in login", cwe=["CWE-89"])
    contexts = [
        RetrievedContext(source="CAPEC-66", text="SQL Injection", score=0.9),
        RetrievedContext(source="CWE-89", text="SQL injection", score=1.0),
    ]
    prompt = build_model_input(cve, contexts)
    assert prompt.startswith("Generate the Explore/Experiment/Exploit attack flow")
    assert "CVE-2024-9999" in prompt
    assert "CWE-89" in prompt
    assert "CAPEC-66" in prompt
    # CWE contexts are not CAPEC candidates and must not be listed as such.
    assert "Candidate attack patterns: CAPEC-66." in prompt


class _FakeTokenizer:
    pad_token_id = 0

    def __call__(self, text, **kwargs):
        class Encoding(dict):
            pass

        return Encoding(input_ids=[1, 2, 3], attention_mask=[1, 1, 1])

    def decode(self, tokens, skip_special_tokens=True):
        return EXPECTED


class _FakeModel:
    def eval(self):
        return self

    def generate(self, **kwargs):
        import torch

        return torch.tensor([[5, 6, 7]])


def test_generator_uses_injected_model_without_download():
    settings = T5ProviderSettings(checkpoint="fake-checkpoint")
    generator = T5Generator(settings, model=_FakeModel(), tokenizer=_FakeTokenizer())
    assert generator.is_loaded

    cve = get_sample_cve("CVE-2024-0002")
    workflow = generator.generate(cve, [])
    assert workflow.provider == "t5"
    assert [step.id.split("-")[0] for step in workflow.steps] == [
        "explore",
        "experiment",
        "exploit",
    ]


def test_generator_defaults_to_configured_checkpoint():
    settings = load_model_settings().providers.t5
    generator = T5Generator(settings)
    assert generator.checkpoint == settings.base_checkpoint
    assert generator.is_loaded is False


def test_generator_reports_missing_stack_helpfully(monkeypatch):
    """Without torch/transformers the error must name the install command."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in {"torch", "transformers"}:
            raise ImportError(f"no {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    generator = T5Generator(T5ProviderSettings(checkpoint="does-not-exist"))
    with pytest.raises(T5UnavailableError, match=r"\.\[t5\]"):
        generator.generate(get_sample_cve("CVE-2024-0001"), [])


def test_factory_returns_t5_provider():
    assert isinstance(get_generator("t5"), T5Generator)
    assert isinstance(get_generator("t5"), GenerationProvider)


def test_rule_based_baseline_is_unchanged():
    cve = get_sample_cve("CVE-2024-0002")
    workflow = RuleBasedGenerator().generate(cve, build_contexts_for_cve(cve))
    assert parse_workflow(workflow).cve_id == "CVE-2024-0002"
    assert len(workflow.steps) >= 3
    assert workflow.provider == "rule_based"


def test_factory_rejects_unknown_provider():
    assert isinstance(get_generator("rule_based"), GenerationProvider)
    with pytest.raises(ValueError):
        get_generator("nope")


def test_llm_stub_still_raises():
    with pytest.raises(NotImplementedError):
        get_generator("llm").generate(get_sample_cve("CVE-2024-0001"), [])


# --- P1.3: structural normalisation and decoding controls ---


def test_normalise_keeps_legitimate_duplicate_phases():
    """Two Experiment steps are normal in MITRE flows and must be preserved."""
    from vuln2action.generation.t5 import normalise_flow_structure

    text = "CAPEC-1 X\n1. Explore: a\n2. Experiment: b\n3. Experiment: c\n4. Exploit: d"
    fixed, report = normalise_flow_structure(text)
    assert fixed.count("Experiment:") == 2
    assert report["dropped_steps"] == 0
    assert report["inserted_phases"] == []


def test_normalise_reorders_without_dropping_steps():
    from vuln2action.generation.t5 import normalise_flow_structure

    text = "CAPEC-2 Y\n1. Explore: a\n2. Exploit: b\n3. Experiment: c"
    fixed, report = normalise_flow_structure(text)
    phases = [line.split(":")[0].split(". ")[1] for line in fixed.splitlines()[1:]]
    assert phases == ["Explore", "Experiment", "Exploit"]
    assert report["dropped_steps"] == 0
    assert sum(1 for line in fixed.splitlines() if line[:1].isdigit()) == 3
    assert "a" in fixed and "b" in fixed and "c" in fixed


def test_normalise_never_inserts_a_missing_phase():
    from vuln2action.generation.t5 import normalise_flow_structure

    text = "CAPEC-3 Z\n1. Explore: only one"
    fixed, report = normalise_flow_structure(text)
    assert "Experiment" not in fixed and "Exploit" not in fixed
    assert report["inserted_phases"] == []


def test_normalise_is_a_noop_for_correct_order():
    from vuln2action.generation.t5 import normalise_flow_structure

    text = "CAPEC-4 W\n1. Explore: a\n2. Experiment: b\n3. Exploit: c"
    fixed, report = normalise_flow_structure(text)
    assert fixed == text
    assert report["reordered_steps"] == 0


def test_workflow_reports_missing_phases_in_safety():
    from vuln2action.generation.t5 import flow_to_workflow

    cve = get_sample_cve("CVE-2024-0002")
    workflow = flow_to_workflow("CAPEC-1 X\n1. Explore: only", cve, [], normalise=False)
    assert "missing phases" in workflow.safety
    assert "Exploit" in workflow.safety


def test_workflow_safety_is_clean_when_all_phases_present():
    from vuln2action.generation.t5 import flow_to_workflow

    cve = get_sample_cve("CVE-2024-0002")
    workflow = flow_to_workflow(EXPECTED, cve, [], normalise=False)
    assert "missing phases" not in workflow.safety


def test_decoding_kwargs_omit_neutral_controls():
    """An untouched config must reproduce P1.2 exactly."""
    generator = T5Generator(T5ProviderSettings(checkpoint="x"))
    kwargs = generator._generation_kwargs()
    assert kwargs["max_new_tokens"] == 256
    assert kwargs["num_beams"] == 4
    assert "no_repeat_ngram_size" not in kwargs
    assert "repetition_penalty" not in kwargs
    assert "length_penalty" not in kwargs


def test_decoding_kwargs_include_improved_controls():
    generator = T5Generator(
        T5ProviderSettings(
            checkpoint="x",
            max_new_tokens=512,
            no_repeat_ngram_size=3,
            repetition_penalty=1.15,
            length_penalty=2.0,
            early_stopping=True,
        )
    )
    kwargs = generator._generation_kwargs()
    assert kwargs["no_repeat_ngram_size"] == 3
    assert kwargs["repetition_penalty"] == 1.15
    assert kwargs["length_penalty"] == 2.0
    assert kwargs["early_stopping"] is True
    assert kwargs["max_new_tokens"] == 512


def test_generator_passes_controls_to_model_generate():
    calls = {}

    class RecordingModel(_FakeModel):
        def generate(self, **kwargs):
            calls.update(kwargs)
            return super().generate(**kwargs)

    generator = T5Generator(
        T5ProviderSettings(checkpoint="x", no_repeat_ngram_size=3, length_penalty=2.0),
        model=RecordingModel(),
        tokenizer=_FakeTokenizer(),
    )
    generator.generate(get_sample_cve("CVE-2024-0002"), [])
    assert calls["no_repeat_ngram_size"] == 3
    assert calls["length_penalty"] == 2.0
