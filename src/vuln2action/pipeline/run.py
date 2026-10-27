"""Typed end-to-end application pipeline."""

from pydantic import BaseModel, ConfigDict

from vuln2action.config import ApplicationSettings
from vuln2action.connectors import load_lab_manifest
from vuln2action.domain import (
    CveRecord,
    EvidenceBundle,
    ExecutionPlan,
    ExecutionResult,
    LabManifest,
    ReproductionResult,
    Workflow,
)
from vuln2action.evidence import EvidenceCollector
from vuln2action.pipeline.analyze import analyze_cve
from vuln2action.reproduction import ReproductionExecutor, ReproductionPlanner, Validator


class PipelineResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    provider: str
    workflow: Workflow
    lab: LabManifest
    plan: ExecutionPlan
    execution: ExecutionResult
    result: ReproductionResult
    evidence: EvidenceBundle

    def to_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


def run_pipeline(
    cve: CveRecord,
    settings: ApplicationSettings,
    provider: str | None = None,
    top_k: int | None = None,
) -> PipelineResult:
    selected_provider = provider or settings.pipeline.default_provider
    selected_top_k = top_k or settings.pipeline.retrieval_top_k
    outcome = analyze_cve(cve, provider=selected_provider, top_k=selected_top_k)
    lab_id = cve.lab_id or settings.pipeline.lab_id
    lab = load_lab_manifest(lab_id)
    if lab.vulnerability_id != cve.cve_id:
        raise ValueError(
            f"Lab {lab_id!r} is registered for {lab.vulnerability_id!r}, not {cve.cve_id!r}"
        )
    plan = ReproductionPlanner().plan(outcome.workflow, lab_id=lab_id)
    allowed_hosts = set(settings.labs.allowed_hosts) | {"lab", "local"}
    execution = ReproductionExecutor(
        simulate=settings.pipeline.simulate_execution,
        allowed_hosts=allowed_hosts,
    ).execute(plan)
    result = Validator().validate(cve.cve_id, lab_id, execution)
    collector = EvidenceCollector()
    collector.add_log(f"Pipeline run for {cve.cve_id} with provider {outcome.provider}")
    for line in execution.log:
        collector.add_log(line)
    collector.add_result(result)
    return PipelineResult(
        cve_id=cve.cve_id,
        provider=outcome.provider,
        workflow=outcome.workflow,
        lab=lab,
        plan=plan,
        execution=execution,
        result=result,
        evidence=collector.bundle(),
    )
