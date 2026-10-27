"""OpenAI-compatible generation provider placeholder."""

from vuln2action.domain import CveRecord, RetrievedContext, Workflow
from vuln2action.generation.base import GenerationProvider


class LLMGenerator(GenerationProvider):
    name = "llm"

    def generate(self, cve: CveRecord, contexts: list[RetrievedContext]) -> Workflow:
        raise NotImplementedError(
            "LLM provider is disabled until credentials and evaluation are configured."
        )
