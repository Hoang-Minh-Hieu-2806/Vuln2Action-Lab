"""CWE (weakness type) records.

TODO(Phase 2): parse CWE catalogue snapshots into CweRecord entries.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CweRecord:
    """Minimal CWE entry."""

    cwe_id: str  # e.g. "CWE-79"
    name: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"cwe_id": self.cwe_id, "name": self.name, "description": self.description}


# Tiny built-in lookup so retrieval/generation have something to work with offline.
_KNOWN: dict[str, CweRecord] = {
    "CWE-79": CweRecord("CWE-79", "Cross-site Scripting (XSS)", "Improper neutralisation of input during web page generation."),
    "CWE-89": CweRecord("CWE-89", "SQL Injection", "Improper neutralisation of special elements used in an SQL command."),
    "CWE-22": CweRecord("CWE-22", "Path Traversal", "Improper limitation of a pathname to a restricted directory."),
}


def lookup_cwe(cwe_id: str) -> CweRecord | None:
    """Return a known CWE record, or None if unknown."""
    return _KNOWN.get(cwe_id)
