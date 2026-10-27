"""Retrieval and generation stage without execution."""

from pydantic import BaseModel, ConfigDict

from vuln2action.domain import CveRecord, RetrievedContext, Workflow
from vuln2action.generation import get_generator
from vuln2action.retrieval.ranker import build_contexts_for_cve


class AnalysisOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve: CveRecord
    contexts: list[RetrievedContext]
    workflow: Workflow
    provider: str


def analyze_cve(
    cve: CveRecord,
    provider: str = "rule_based",
    top_k: int = 3,
    backend: str = "semantic",
) -> AnalysisOutcome:
    generator = get_generator(provider)
    contexts = build_contexts_for_cve(cve, top_k=top_k, backend=backend)
    workflow = generator.generate(cve, contexts)
    return AnalysisOutcome(cve=cve, contexts=contexts, workflow=workflow, provider=generator.name)
