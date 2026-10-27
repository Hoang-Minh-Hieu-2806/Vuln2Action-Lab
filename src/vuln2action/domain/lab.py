"""Declarative metadata for an isolated lab."""

from pydantic import BaseModel, ConfigDict, Field


class LabManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    lab_id: str
    vulnerability_id: str
    kind: str = "demo"
    status: str = "placeholder"
    compose_file: str = "docker-compose.yml"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    setup_command: list[str] = Field(default_factory=list)
    validation_command: list[str] = Field(default_factory=list)
    teardown_command: list[str] = Field(default_factory=list)
    has_patched_counterfactual: bool = False
