"""Local T5 generation provider placeholder."""

from vuln2action.domain import CveRecord, RetrievedContext, Workflow
from vuln2action.generation.base import GenerationProvider


class T5Generator(GenerationProvider):
    name = "t5"

    def generate(self, cve: CveRecord, contexts: list[RetrievedContext]) -> Workflow:
        raise NotImplementedError(
            "T5 provider is disabled until a versioned checkpoint is configured."
        )
