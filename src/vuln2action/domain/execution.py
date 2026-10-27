"""Typed execution-plan contracts."""

from pydantic import BaseModel, ConfigDict, Field


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    action: str
    detail: str
    target: str = "localhost"
    lab_id: str


class ExecutionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    lab_id: str
    steps: list[PlanStep] = Field(min_length=1)


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    simulated: bool
    completed: bool
    log: list[str] = Field(default_factory=list)
    steps_executed: int = Field(default=0, ge=0)
    error: str | None = None
