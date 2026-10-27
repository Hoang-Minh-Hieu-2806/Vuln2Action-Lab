"""Strict model-output parsing."""

from __future__ import annotations

import json
from typing import Any

from vuln2action.domain import Workflow


def parse_workflow(raw: Workflow | dict[str, Any] | str) -> Workflow:
    if isinstance(raw, Workflow):
        return raw
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("workflow output is not valid JSON") from exc
    return Workflow.model_validate(raw)
