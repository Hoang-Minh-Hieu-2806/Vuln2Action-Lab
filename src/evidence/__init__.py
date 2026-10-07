"""Evidence layer: collect command output, HTTP metadata, logs, verdicts."""
from src.evidence.collector import EvidenceCollector
from src.evidence.reporter import ReportPaths, save_report

__all__ = ["EvidenceCollector", "ReportPaths", "save_report"]
