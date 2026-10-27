"""Validated application configuration and repository paths."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

try:
    import yaml
except ImportError:  # pragma: no cover - JSON-compatible YAML remains supported
    yaml = None  # type: ignore[assignment]


class PipelineSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_provider: str = "rule_based"
    retrieval_top_k: int = Field(default=3, ge=1)
    lab_id: str = "cve-001"
    simulate_execution: bool = True


class RetrievalSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backends: list[str] = Field(default_factory=lambda: ["keyword", "tfidf"])
    top_k: int = Field(default=3, ge=1)


class LabSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    network: str = "vuln2action-lab-net"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    timeout_seconds: int = Field(default=120, ge=1)


class EvidenceSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output_dir: str = "results"
    formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])


class ApplicationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    retrieval: RetrievalSettings = Field(default_factory=RetrievalSettings)
    labs: LabSettings = Field(default_factory=LabSettings)
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_yaml(path: str | Path) -> dict[str, object]:
    with Path(path).open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) if yaml is not None else json.load(handle)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise TypeError(f"Expected mapping in YAML file: {path}")
    return raw


def load_settings(path: str | Path | None = None) -> ApplicationSettings:
    config_path = Path(path) if path else project_root() / "config" / "settings.yaml"
    return ApplicationSettings.model_validate(load_yaml(config_path))
