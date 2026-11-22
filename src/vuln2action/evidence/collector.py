"""Build an immutable, serialisable evidence bundle."""

from typing import Any

from vuln2action.domain import (
    EvidenceBundle,
    ExecutionPlan,
    HttpEvidence,
    ReproductionResult,
    Workflow,
)


class EvidenceCollector:
    def __init__(self) -> None:
        self._bundle = EvidenceBundle()

    def add_command_output(self, step_id: str, output: str) -> None:
        self._bundle.command_outputs[step_id] = output

    def add_http_metadata(self, url: str, status: int, notes: str = "") -> None:
        self._bundle.http.append(HttpEvidence(url=url, status=status, notes=notes))

    def add_log(self, message: str) -> None:
        self._bundle.logs.append(message)

    def add_generation(self, data: dict[str, Any]) -> None:
        self._bundle.generation = data

    def add_workflow(self, workflow: Workflow) -> None:
        self._bundle.workflow = workflow.model_dump(mode="json")

    def add_plan(self, plan: ExecutionPlan) -> None:
        self._bundle.plan = plan.model_dump(mode="json")

    def add_result(self, result: ReproductionResult) -> None:
        self._bundle.validation_result = result.model_dump(mode="json")

    def bundle(self) -> EvidenceBundle:
        return self._bundle.model_copy(deep=True)
