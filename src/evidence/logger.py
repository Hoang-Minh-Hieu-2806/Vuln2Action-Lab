"""Evidence run logger (thin wrapper over shared logging)."""
from __future__ import annotations

from src.utils.logging import get_logger


def get_evidence_logger(name: str = "vuln2action.evidence"):
    """Return the evidence logger. TODO(Phase 6): file handler into results/."""
    return get_logger(name)
