"""Configuration loading (YAML + env overrides).

TODO(Phase 2): add validation with pydantic-settings if needed.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


def project_root() -> Path:
    """Return the repository root (parent of src/)."""
    return Path(__file__).resolve().parents[2]


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load a YAML file into a dict. Requires PyYAML."""
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def load_settings(path: str | Path | None = None) -> dict[str, Any]:
    """Load config/settings.yaml (default location under repo root)."""
    root = project_root()
    cfg_path = Path(path) if path else root / "config" / "settings.yaml"
    return load_yaml(cfg_path)


def load_models(path: str | Path | None = None) -> dict[str, Any]:
    """Load config/models.yaml."""
    root = project_root()
    cfg_path = Path(path) if path else root / "config" / "models.yaml"
    return load_yaml(cfg_path)


def get_env(name: str, default: str = "") -> str:
    """Read an env var with a default (never raise for missing secrets)."""
    return os.environ.get(name, default)
