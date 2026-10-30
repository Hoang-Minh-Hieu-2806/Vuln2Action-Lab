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
    default_backend: str = "semantic"
    backends: list[str] = Field(default_factory=lambda: ["keyword", "tfidf", "semantic"])
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


class T5ProviderSettings(BaseModel):
    """Local T5 generation settings (no download happens implicitly).

    The decoding knobs exist because the first fine-tuned checkpoint loops inside
    a step and runs into the token cap before reaching the Exploit phase
    (see ``docs/generation-quality.md``). Defaults stay at the original values so
    existing checkpoints reproduce their P1.2 numbers; P1.3 turns them on
    explicitly and measures both.
    """

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    base_checkpoint: str = "t5-small"
    checkpoint: str = ""
    max_input_length: int = Field(default=512, ge=1)
    max_target_length: int = Field(default=512, ge=1)
    max_new_tokens: int = Field(default=256, ge=1)
    num_beams: int = Field(default=4, ge=1)
    device: str = "cpu"
    allow_download: bool = False
    # --- decoding controls (P1.3) ---
    no_repeat_ngram_size: int = Field(default=0, ge=0)
    repetition_penalty: float = Field(default=1.0, ge=0.0)
    length_penalty: float = 1.0
    early_stopping: bool = False
    min_new_tokens: int = Field(default=0, ge=0)
    # Reorder steps into Explore -> Experiment -> Exploit before building a
    # Workflow. Reorders only: never inserts a missing phase, never drops or
    # merges a step (two Experiment steps are legitimate).
    normalise_output: bool = False


class GenerationProvidersSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_based: dict[str, object] = Field(default_factory=lambda: {"enabled": True})
    llm: dict[str, object] = Field(default_factory=dict)
    t5: T5ProviderSettings = Field(default_factory=T5ProviderSettings)


class GenerationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    providers: GenerationProvidersSettings = Field(default_factory=GenerationProvidersSettings)


class ApplicationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    retrieval: RetrievalSettings = Field(default_factory=RetrievalSettings)
    labs: LabSettings = Field(default_factory=LabSettings)
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)
    generation: GenerationSettings = Field(default_factory=GenerationSettings)


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


def load_model_settings(path: str | Path | None = None) -> GenerationSettings:
    """Load ``config/models.yaml`` (generation provider settings only)."""
    config_path = Path(path) if path else project_root() / "config" / "models.yaml"
    return GenerationSettings.model_validate(load_yaml(config_path))
