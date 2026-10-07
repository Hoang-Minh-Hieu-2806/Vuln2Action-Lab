"""Pathlib-based filesystem helpers (no hard-coded absolute paths)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def ensure_dir(path: str | Path) -> Path:
    """Create a directory (parents included) and return it."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_json(path: str | Path) -> Any:
    """Read a JSON file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | Path, data: Any, indent: int = 2) -> Path:
    """Write data as JSON, creating parent dirs as needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)
    return p


def repo_path(*parts: str) -> Path:
    """Resolve a path relative to the repository root."""
    root = Path(__file__).resolve().parents[2]
    return root.joinpath(*parts)
