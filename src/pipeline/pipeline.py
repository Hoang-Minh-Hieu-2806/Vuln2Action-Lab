"""Full pipeline: analyze -> plan -> execute(sim) -> validate -> evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.evidence.collector import EvidenceCollector
from src.ingestion.cve import CveRecord
from src.pipeline.analyze import analyze_cve
from src.reproduction.executor import ReproductionExecutor
from src.reproduction.planner import ReproductionPlanner
from src.reproduction.result import ReproductionResult
from src.reproduction.validator import Validator


@dataclass
class PipelineResult:
    outcome_dict: dict[str, Any]
    plan: list[dict[str, str]]
    exec_info: dict[str, Any]
    result: ReproductionResult
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.outcome_dict["cve"]["cve_id"],
            "provider": self.outcome_dict["provider"],
            "workflow": self.outcome_dict["workflow"],
            "plan": self.plan,
            "execution": self.exec_info,
            "result": self.result.to_dict(),
            "evidence": self.evidence,
        }


def run_pipeline(cve: CveRecord, provider: str = "rule_based", top_k: int = 3) -> PipelineResult:
    """End-to-end offline run over one CVE record."""
    outcome = analyze_cve(cve, provider=provider, top_k=top_k)
    lab_id = cve.lab_id or "cve-001"
    planner = ReproductionPlanner()
    plan = planner.plan(outcome.workflow, lab_id=lab_id)
    exec_info = ReproductionExecutor(simulate=True).execute(plan)
    result = Validator().validate(cve.cve_id, lab_id, exec_info)
    collector = EvidenceCollector()
    collector.add_log(f"Pipeline run for {cve.cve_id} with provider {outcome.provider}")
    for line in exec_info.get("log", []):
        collector.add_log(line)
    collector.add_result(result)
    evidence = collector.bundle()
    return PipelineResult(
        outcome_dict=outcome.to_dict(), plan=plan,
        exec_info=exec_info, result=result, evidence=evidence,
    )
