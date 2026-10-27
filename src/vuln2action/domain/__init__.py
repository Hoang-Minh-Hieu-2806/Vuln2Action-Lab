"""Typed contracts shared by all pipeline stages."""

from vuln2action.domain.cve import CpeRecord, CveRecord
from vuln2action.domain.evidence import EvidenceBundle, HttpEvidence
from vuln2action.domain.execution import ExecutionPlan, ExecutionResult, PlanStep
from vuln2action.domain.knowledge import (
    CapecRecord,
    CweRecord,
    ExploitReference,
    KnowledgeDocument,
    RetrievedContext,
)
from vuln2action.domain.lab import LabManifest
from vuln2action.domain.workflow import (
    ReproductionResult,
    ReproductionStatus,
    Workflow,
    WorkflowStep,
)

__all__ = [
    "CapecRecord",
    "CpeRecord",
    "CveRecord",
    "CweRecord",
    "EvidenceBundle",
    "ExecutionPlan",
    "ExecutionResult",
    "ExploitReference",
    "HttpEvidence",
    "KnowledgeDocument",
    "LabManifest",
    "PlanStep",
    "ReproductionResult",
    "ReproductionStatus",
    "RetrievedContext",
    "Workflow",
    "WorkflowStep",
]
