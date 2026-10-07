"""Reproduction planner: workflow dict -> ordered executable plan."""
from __future__ import annotations

from typing import Any


class ReproductionPlanner:
    """Turn a generation workflow into a lab plan. TODO(Phase 5): lab-specific plans."""

    def plan(self, workflow: dict[str, Any], lab_id: str = "") -> list[dict[str, str]]:
        steps = workflow.get("steps", [])
        plan: list[dict[str, str]] = []
        for s in steps:
            plan.append(
                {
                    "id": str(s.get("id", "step")),
                    "action": str(s.get("action", "")),
                    "detail": str(s.get("detail", "")),
                    "target": "localhost",
                    "lab_id": lab_id or str(workflow.get("lab_id", "cve-001")),
                }
            )
        return plan
