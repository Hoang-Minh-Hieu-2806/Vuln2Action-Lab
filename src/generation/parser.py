"""Workflow parsing/validation helpers."""
from __future__ import annotations

from typing import Any


def new_workflow_skeleton(cve_id: str, provider: str = "rule_based") -> dict[str, Any]:
    """Return the canonical workflow dict shape."""
    return {
        "cve_id": cve_id,
        "provider": provider,
        "steps": [],
        "context_summary": "",
        "safety": "localhost lab only",
    }


def parse_workflow(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate/normalise a workflow dict (raises ValueError on bad shape)."""
    if not isinstance(raw, dict):
        raise ValueError("workflow must be a dict")
    if not raw.get("cve_id"):
        raise ValueError("workflow missing 'cve_id'")
    steps = raw.get("steps", [])
    if not isinstance(steps, list) or not steps:
        raise ValueError("workflow must contain a non-empty 'steps' list")
    # TODO(Phase 4): stricter per-step schema validation.
    return raw
