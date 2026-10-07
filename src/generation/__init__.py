"""Generation layer: provider-agnostic workflow generation.

Usage:
    generator = RuleBasedGenerator()   # Phase 1 default (works offline)
    # generator = LLMGenerator()       # Phase 4 (needs API key)
    # generator = T5Generator()        # Phase 4 (needs local checkpoint)

The pipeline depends only on GenerationProvider, never on a concrete model.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class GenerationProvider(ABC):
    """Interface every generator backend must implement."""

    name: str = "base"

    @abstractmethod
    def generate(self, cve: object, contexts: list[object]) -> dict[str, Any]:
        """Return a reproduction workflow dict for the given CVE + contexts."""
        raise NotImplementedError


class RuleBasedGenerator(GenerationProvider):
    """Deterministic baseline: builds workflow steps from CVE/CWE/CPE signals."""

    name = "rule_based"

    def generate(self, cve: object, contexts: list[object]) -> dict[str, Any]:
        from src.generation.prompts import build_context_summary
        from src.generation.parser import new_workflow_skeleton

        cve_id = getattr(cve, "cve_id", "UNKNOWN")
        description = getattr(cve, "description", "")
        cwe_list = list(getattr(cve, "cwe", []))
        lab_id = getattr(cve, "lab_id", "cve-001") or "cve-001"
        summary = build_context_summary(contexts)
        steps: list[dict[str, str]] = [
            {"id": "lab-up", "action": "Start the isolated lab",
             "detail": f"docker compose -f labs/{lab_id}/docker-compose.yml up -d --build (localhost only)"},
            {"id": "inspect", "action": "Inspect target service",
             "detail": f"Review labs/{lab_id}/target/ and confirm it serves on localhost. CVE: {cve_id}."},
            {"id": "probe", "action": "Send benign probe request",
             "detail": f"Probe the lab endpoint with a harmless input related to: {description[:120]}"},
            {"id": "validate", "action": "Run lab validation script",
             "detail": f"Execute labs/{lab_id}/validation/ check; record PASS/FAIL with evidence."},
            {"id": "teardown", "action": "Collect evidence and stop lab",
             "detail": "Save logs/outputs to results/, then docker compose down."},
        ]
        if "CWE-79" in cwe_list:
            steps[2]["detail"] += " Focus: reflected input handling (CWE-79 XSS)."
        if "CWE-89" in cwe_list:
            steps[2]["detail"] += " Focus: login input handling (CWE-89 SQLi)."
        if "CWE-22" in cwe_list:
            steps[2]["detail"] += " Focus: file path handling (CWE-22 traversal)."
        workflow = new_workflow_skeleton(cve_id, provider=self.name)
        workflow["steps"] = steps
        workflow["context_summary"] = summary
        workflow["safety"] = "localhost lab only; no real-world targets"
        return workflow


def get_generator(name: str) -> GenerationProvider:
    """Factory: return a generator by name without coupling callers to models."""
    key = (name or "rule_based").lower()
    if key in ("rule_based", "rule", "baseline"):
        return RuleBasedGenerator()
    if key in ("llm", "api"):
        from src.generation.llm import LLMGenerator

        return LLMGenerator()
    if key in ("t5", "local"):
        from src.generation.t5 import T5Generator

        return T5Generator()
    raise ValueError(f"Unknown generator provider: {name!r}")
