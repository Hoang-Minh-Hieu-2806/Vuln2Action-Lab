"""Generation interface and provider factory."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vuln2action.domain import CveRecord, RetrievedContext, Workflow


class GenerationProvider(ABC):
    name = "base"

    @abstractmethod
    def generate(self, cve: CveRecord, contexts: list[RetrievedContext]) -> Workflow:
        raise NotImplementedError


def get_generator(name: str) -> GenerationProvider:
    key = (name or "rule_based").lower()
    if key in {"rule_based", "rule", "baseline"}:
        from vuln2action.generation.rule_based import RuleBasedGenerator

        return RuleBasedGenerator()
    if key in {"llm", "api"}:
        from vuln2action.generation.llm import LLMGenerator

        return LLMGenerator()
    if key in {"t5", "local"}:
        from vuln2action.generation.t5 import T5Generator

        return T5Generator()
    raise ValueError(f"Unknown generator provider: {name!r}")
