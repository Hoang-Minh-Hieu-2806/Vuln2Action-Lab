"""Analyze stage: ingestion -> retrieval -> generation (no execution)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.generation import GenerationProvider, get_generator
from src.ingestion.cve import CveRecord
from src.retrieval.ranker import RetrievedContext, build_contexts_for_cve


@dataclass
class AnalysisOutcome:
    cve: CveRecord
    contexts: list[RetrievedContext]
    workflow: dict[str, Any]
    provider: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve.to_dict(),
            "contexts": [c.to_dict() for c in self.contexts],
            "workflow": self.workflow,
            "provider": self.provider,
        }


def analyze_cve(cve: CveRecord, provider: str = "rule_based", top_k: int = 3) -> AnalysisOutcome:
    """Run ingest-already CVE through retrieval + generation."""
    generator: GenerationProvider = get_generator(provider)
    contexts = build_contexts_for_cve(cve, top_k=top_k)
    workflow = generator.generate(cve, contexts)
    workflow.setdefault("lab_id", cve.lab_id or "cve-001")
    return AnalysisOutcome(cve=cve, contexts=contexts, workflow=workflow, provider=generator.name)
