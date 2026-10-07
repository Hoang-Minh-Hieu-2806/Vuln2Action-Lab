"""CVE schemas. TODO(Phase 8): flesh out request/response models."""
from __future__ import annotations

try:
    from pydantic import BaseModel

    class CveResponse(BaseModel):
        cve_id: str
        description: str = ""
        lab_id: str = ""
except ImportError:  # pydantic optional until API phase
    CveResponse = object  # type: ignore[assignment,misc]
