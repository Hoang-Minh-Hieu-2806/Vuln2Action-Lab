"""Convert a validated workflow into a lab-scoped execution plan."""

from vuln2action.domain import ExecutionPlan, PlanStep, Workflow


class ReproductionPlanner:
    def plan(self, workflow: Workflow, lab_id: str | None = None) -> ExecutionPlan:
        selected_lab = lab_id or workflow.lab_id
        if not selected_lab:
            raise ValueError("A lab_id is required before a workflow can be planned")
        return ExecutionPlan(
            cve_id=workflow.cve_id,
            lab_id=selected_lab,
            steps=[
                PlanStep(
                    id=step.id,
                    action=step.action,
                    detail=step.detail,
                    target="localhost",
                    lab_id=selected_lab,
                )
                for step in workflow.steps
            ],
        )
