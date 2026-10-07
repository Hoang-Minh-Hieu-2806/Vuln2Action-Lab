"""Prompt templates for LLM/T5 generation (Phase 4). Centralised here."""
from __future__ import annotations


def build_context_summary(contexts: list[object]) -> str:
    """Render retrieved contexts into a short human-readable summary."""
    lines: list[str] = []
    for ctx in contexts:
        source = getattr(ctx, "source", "?")
        text = getattr(ctx, "text", "")
        lines.append(f"- [{source}] {text}")
    return "\n".join(lines) if lines else "(no additional context)"


def build_generation_prompt(cve: object, contexts: list[object]) -> str:
    """Build the prompt used by LLM/T5 backends. TODO(Phase 4): refine."""
    summary = build_context_summary(contexts)
    return (
        "You are a defensive security assistant working ONLY with an isolated "
        "Docker lab on localhost. Given the CVE and context below, produce a "
        "numbered, benign reproduction workflow (start lab, inspect, benign "
        "probe, validate, teardown). Never target real-world systems.\n\n"
        f"CVE: {getattr(cve, 'cve_id', '?')}\n"
        f"Description: {getattr(cve, 'description', '')}\n"
        f"Context:\n{summary}\n"
    )
