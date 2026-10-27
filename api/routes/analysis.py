"""Read-only vulnerability analysis route."""

from __future__ import annotations

from fastapi import APIRouter

from vuln2action.config import load_settings
from vuln2action.domain import CveRecord
from vuln2action.pipeline import analyze_cve

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("")
def analyze(request: CveRecord) -> dict[str, object]:
    settings = load_settings()
    outcome = analyze_cve(
        request,
        provider=settings.pipeline.default_provider,
        top_k=settings.pipeline.retrieval_top_k,
        backend=settings.retrieval.default_backend,
    )
    return outcome.model_dump(mode="json")
