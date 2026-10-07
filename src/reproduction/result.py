"""Typed reproduction result."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ReproductionStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class ReproductionResult:
    cve_id: str
    lab_id: str
    status: ReproductionStatus
    steps_executed: int = 0
    details: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "lab_id": self.lab_id,
            "status": self.status.value,
            "steps_executed": self.steps_executed,
            "details": self.details,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }
