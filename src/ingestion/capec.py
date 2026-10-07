"""CAPEC (attack pattern) records.

TODO(Phase 2/3): link CWE -> CAPEC entries for richer retrieval context.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CapecRecord:
    """Minimal CAPEC entry."""

    capec_id: str  # e.g. "CAPEC-63"
    name: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"capec_id": self.capec_id, "name": self.name, "description": self.description}
