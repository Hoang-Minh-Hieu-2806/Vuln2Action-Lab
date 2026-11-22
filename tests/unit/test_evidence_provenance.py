"""Checkpoint provenance survives generation, evidence and serialization."""

import json

from vuln2action.config import T5ProviderSettings, load_settings
from vuln2action.connectors import get_sample_cve
from vuln2action.domain import (
    CveRecord,
    EvidenceBundle,
    ReproductionStatus,
    Workflow,
)
from vuln2action.generation.t5 import GeneratedFlow, T5Generator, flow_to_workflow
from vuln2action.pipeline import run_pipeline

FLOW_TEXT = (
    "1. Explore: [Survey the target] Collect public information.\n"
    "2. Experiment: [Probe the input] Send a benign marker.\n"
    "3. Exploit: [Trigger the flaw] Confirm the reflected output.\n"
)


class _FakeTokenizer:
    def __call__(self, *args, **kwargs):
        return {"input_ids": [1], "attention_mask": [1]}

    def decode(self, *args, **kwargs):
        return FLOW_TEXT


class _FakeModel:
    def generate(self, **kwargs):
        return [[5, 6, 7]]


def test_evidence_keeps_checkpoint_metadata():
    bundle = EvidenceBundle(checkpoint_id="models/stage1-final")
    restored = EvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    assert restored.checkpoint_id == "models/stage1-final"


def test_old_evidence_without_checkpoint_loads():
    old = {"logs": ["old run"], "command_outputs": {}, "http": []}
    restored = EvidenceBundle.model_validate(old)
    assert restored.checkpoint_id is None
    assert restored.logs == ["old run"]


def test_flow_to_workflow_keeps_checkpoint():
    cve = CveRecord(cve_id="CVE-2024-0001", description="demo")
    flow = GeneratedFlow(text=FLOW_TEXT, checkpoint="models/stage1-final", steps=[])
    workflow = flow_to_workflow(flow.text, cve, [], checkpoint_id=flow.checkpoint)
    assert workflow.checkpoint_id == "models/stage1-final"


def test_t5_generate_carries_checkpoint_into_workflow():
    cve = CveRecord(cve_id="CVE-2024-0001", description="demo")
    generator = T5Generator(
        T5ProviderSettings(checkpoint="fake-checkpoint"),
        model=_FakeModel(),
        tokenizer=_FakeTokenizer(),
    )
    workflow = generator.generate(cve, [])
    assert workflow.checkpoint_id == "fake-checkpoint"


def test_serialization_roundtrip_keeps_checkpoint():
    cve = CveRecord(cve_id="CVE-2024-0001", description="demo")
    workflow = flow_to_workflow(FLOW_TEXT, cve, [], checkpoint_id="ckpt-roundtrip")
    restored = Workflow.model_validate(json.loads(workflow.model_dump_json()))
    assert restored.checkpoint_id == "ckpt-roundtrip"

    bundle = EvidenceBundle(
        checkpoint_id="ckpt-roundtrip", workflow=workflow.model_dump(mode="json")
    )
    restored_bundle = EvidenceBundle.model_validate(json.loads(bundle.model_dump_json()))
    assert restored_bundle.checkpoint_id == "ckpt-roundtrip"
    assert restored_bundle.workflow["checkpoint_id"] == "ckpt-roundtrip"


def test_pipeline_without_checkpoint_does_not_fail():
    outcome = run_pipeline(
        get_sample_cve("CVE-2024-0001"),
        settings=load_settings(),
        provider="rule_based",
    )
    assert outcome.result.status is ReproductionStatus.SIMULATED
    assert outcome.evidence.checkpoint_id is None
    assert outcome.workflow.checkpoint_id is None
