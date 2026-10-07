"""LLM/API-based generator stub (Phase 4).

TODO(Phase 4): implement OpenAI-compatible client using config/models.yaml
+ LLM_API_KEY env var. Keep disabled until then.
"""
from __future__ import annotations

from typing import Any

from src.generation import GenerationProvider


class LLMGenerator(GenerationProvider):
    name = "llm"

    def __init__(self, model: str = "", api_base: str = "") -> None:
        self.model = model
        self.api_base = api_base

    def generate(self, cve: object, contexts: list[object]) -> dict[str, Any]:
        raise NotImplementedError(
            "LLMGenerator is not configured in Phase 1. Set LLM_API_KEY/LLM_MODEL "
            "and implement the API client (see config/models.yaml), or use "
            "RuleBasedGenerator instead."
        )
