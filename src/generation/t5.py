"""Local T5 generator stub (Phase 4, optional).

TODO(Phase 4): load a small local checkpoint (e.g. t5-small) with
transformers/torch kept as OPTIONAL deps. Never hard-code T5 as the only model.
"""
from __future__ import annotations

from typing import Any

from src.generation import GenerationProvider


class T5Generator(GenerationProvider):
    name = "t5"

    def __init__(self, checkpoint: str = "t5-small") -> None:
        self.checkpoint = checkpoint

    def generate(self, cve: object, contexts: list[object]) -> dict[str, Any]:
        raise NotImplementedError(
            "T5Generator is not implemented in Phase 1. Add transformers/torch "
            "optionally and wire config/models.yaml, or use RuleBasedGenerator."
        )
