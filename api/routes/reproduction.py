"""Simulation-only reproduction route."""
from __future__ import annotations

from fastapi import APIRouter

from vuln2action.config import load_settings
from vuln2action.domain import CveRecord
from vuln2action.pipeline import run_pipeline

router = APIRouter(prefix="/reproduction", tags=["reproduction"])


@router.post("")
def reproduce(request: CveRecord) -> dict[str, object]:
    settings = load_settings()
    if not settings.pipeline.simulate_execution:
        raise RuntimeError("The API only exposes simulation until guarded Docker execution exists")
    return run_pipeline(request, settings=settings).to_dict()
