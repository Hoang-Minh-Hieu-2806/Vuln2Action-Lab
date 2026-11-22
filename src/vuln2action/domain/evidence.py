"""Evidence bundle contracts."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HttpEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    status: int
    notes: str = ""


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collected_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    logs: list[str] = Field(default_factory=list)
    command_outputs: dict[str, str] = Field(default_factory=dict)
    http: list[HttpEvidence] = Field(default_factory=list)
    generation: dict[str, Any] | None = None
    workflow: dict[str, Any] | None = None
    plan: dict[str, Any] | None = None
    checkpoint_id: str | None = None
    validation_result: dict[str, Any] | None = None
