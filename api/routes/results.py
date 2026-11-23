"""Read previously generated local reports."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request

from vuln2action.utils.filesystem import read_json, repo_path

router = APIRouter(prefix="/results", tags=["results"])


@router.get("/{run_id}")
def read_result(run_id: str, http_request: Request) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise HTTPException(status_code=400, detail="Invalid run id")
    settings = http_request.app.state.settings
    report_path = repo_path(settings.evidence.output_dir, run_id, "report.json")
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="Run not found")
    result = read_json(report_path)
    if not isinstance(result, dict):
        raise HTTPException(status_code=500, detail="Invalid report format")
    return result
