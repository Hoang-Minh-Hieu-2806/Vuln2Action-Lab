"""Evidence logger facade."""

from vuln2action.utils.logging import get_logger


def get_evidence_logger(name: str = "vuln2action.evidence"):
    return get_logger(name)
