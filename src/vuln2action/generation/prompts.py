"""Prompt/context rendering kept separate from provider implementations."""

from vuln2action.domain import RetrievedContext


def build_context_summary(contexts: list[RetrievedContext]) -> str:
    return "\n".join(f"[{item.source}] {item.text}" for item in contexts)


def build_generation_prompt(cve_id: str, description: str, context_summary: str) -> str:
    return (
        "Generate a structured, non-destructive workflow for an isolated localhost lab.\n"
        f"Vulnerability: {cve_id}\nDescription: {description}\nContext:\n{context_summary}"
    )
