"""Read-only vulnerability analysis route."""

from __future__ import annotations

from fastapi import APIRouter, Request

from vuln2action.domain import CveRecord
from vuln2action.pipeline import analyze_cve

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("")
def analyze(request: CveRecord, http_request: Request) -> dict[str, object]:
    settings = http_request.app.state.settings
    outcome = analyze_cve(
        request,
        provider=settings.pipeline.default_provider,
        top_k=settings.pipeline.retrieval_top_k,
        backend=settings.retrieval.default_backend,
    )
    return outcome.model_dump(mode="json")
