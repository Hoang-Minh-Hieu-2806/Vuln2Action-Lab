"""Generation interface and provider factory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from threading import Lock

from vuln2action.config import load_model_settings
from vuln2action.domain import CveRecord, RetrievedContext, Workflow


class GenerationProvider(ABC):
    name = "base"

    @abstractmethod
    def generate(self, cve: CveRecord, contexts: list[RetrievedContext]) -> Workflow:
        raise NotImplementedError


_GENERATOR_CACHE: dict[tuple[str, tuple[tuple[str, object], ...]], GenerationProvider] = {}
_CACHE_LOCK = Lock()


def _t5_cache_key() -> tuple[str, tuple[tuple[str, object], ...]]:
    settings = load_model_settings().providers.t5
    return ("t5", tuple(sorted(settings.model_dump(mode="json").items())))


def clear_generator_cache() -> None:
    """Drop cached providers so the next request re-reads model configuration."""
    with _CACHE_LOCK:
        _GENERATOR_CACHE.clear()


def get_generator(name: str) -> GenerationProvider:
    key = (name or "rule_based").lower()
    if key in {"rule_based", "rule", "baseline"}:
        from vuln2action.generation.rule_based import RuleBasedGenerator

        return RuleBasedGenerator()
    if key in {"llm", "api"}:
        from vuln2action.generation.llm import LLMGenerator

        return LLMGenerator()
    if key in {"t5", "local"}:
        cache_key = _t5_cache_key()
        with _CACHE_LOCK:
            cached = _GENERATOR_CACHE.get(cache_key)
            if cached is None:
                from vuln2action.generation.t5 import T5Generator

                cached = T5Generator()
                _GENERATOR_CACHE[cache_key] = cached
            return cached
    raise ValueError(f"Unknown generator provider: {name!r}")
