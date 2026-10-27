"""Persist a report in a run-specific directory."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from vuln2action.utils.filesystem import ensure_dir, repo_path, write_json


class ReportPaths(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_dir: str
    json_path: str
    markdown_path: str


def _safe_run_id(run_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id.strip()).strip(".-")
    if not safe:
        raise ValueError("run_id must contain at least one safe character")
    return safe


def save_report(
    run_id: str,
    payload: dict[str, Any],
    output_dir: str | Path = "results",
) -> ReportPaths:
    root = Path(output_dir)
    if not root.is_absolute():
        root = repo_path(str(root))
    run_dir = ensure_dir(root / _safe_run_id(run_id))
    json_path = write_json(run_dir / "report.json", payload)
    markdown_path = run_dir / "report.md"
    result = payload.get("result", {})
    markdown_path.write_text(
        f"# Vuln2Action-Lab run: {run_id}\n\n"
        f"- Vulnerability: {payload.get('cve_id', '?')}\n"
        f"- Provider: {payload.get('provider', '?')}\n"
        f"- Verdict: **{result.get('status', 'UNKNOWN')}**\n\n"
        "The JSON report contains the complete typed evidence bundle.\n",
        encoding="utf-8",
    )
    return ReportPaths(
        run_dir=str(run_dir),
        json_path=str(json_path),
        markdown_path=str(markdown_path),
    )
