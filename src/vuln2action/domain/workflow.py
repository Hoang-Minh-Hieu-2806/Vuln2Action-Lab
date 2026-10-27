"""Generated workflow and final validation contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    action: str
    detail: str

    @field_validator("id", "action", "detail")
    @classmethod
    def must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("workflow step fields must not be blank")
        return value


class Workflow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    provider: str
    steps: list[WorkflowStep] = Field(min_length=1)
    context_summary: str = ""
    safety: str = "localhost lab only"
    lab_id: str = ""


class ReproductionStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    SIMULATED = "SIMULATED"


class ReproductionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    lab_id: str
    status: ReproductionStatus
    steps_executed: int = Field(default=0, ge=0)
    details: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
