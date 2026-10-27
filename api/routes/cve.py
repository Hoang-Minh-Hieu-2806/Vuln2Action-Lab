"""Read-only sample CVE routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from vuln2action.connectors import get_sample_cve, load_sample_cves

router = APIRouter(prefix="/cve", tags=["cve"])


@router.get("")
def list_cves() -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in load_sample_cves()]


@router.get("/{cve_id}")
def read_cve(cve_id: str) -> dict[str, object]:
    try:
        return get_sample_cve(cve_id).model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
