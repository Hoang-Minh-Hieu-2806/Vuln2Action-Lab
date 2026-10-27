"""Repository-local filesystem helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln2action.config import project_root


def ensure_dir(path: str | Path) -> Path:
    resolved = Path(path)
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def read_json(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, data: Any, indent: int = 2) -> Path:
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=indent, ensure_ascii=False)
    return resolved


def repo_path(*parts: str) -> Path:
    return project_root().joinpath(*parts)
