"""Deterministic baseline generator."""

from vuln2action.domain import CveRecord, RetrievedContext, Workflow, WorkflowStep
from vuln2action.generation.base import GenerationProvider
from vuln2action.generation.prompts import build_context_summary


class RuleBasedGenerator(GenerationProvider):
    name = "rule_based"

    def generate(self, cve: CveRecord, contexts: list[RetrievedContext]) -> Workflow:
        focus = "Inspect the input handling described by the vulnerability record."
        if "CWE-79" in cve.cwe:
            focus = "Inspect reflected-output encoding in the isolated XSS demo."
        elif "CWE-89" in cve.cwe:
            focus = "Inspect parameterised query handling in the isolated SQL injection demo."
        elif "CWE-22" in cve.cwe:
            focus = "Inspect path normalisation in the isolated traversal demo."
        lab_id = cve.lab_id or "cve-001"
        return Workflow(
            cve_id=cve.cve_id,
            provider=self.name,
            lab_id=lab_id,
            context_summary=build_context_summary(contexts),
            safety="localhost lab only; no real-world targets",
            steps=[
                WorkflowStep(
                    id="lab-up",
                    action="Start isolated lab",
                    detail=f"Start lab {lab_id} from its checked-in manifest.",
                ),
                WorkflowStep(
                    id="inspect",
                    action="Inspect target service",
                    detail="Confirm the expected demo version and localhost binding.",
                ),
                WorkflowStep(id="probe", action="Run benign validation probe", detail=focus),
                WorkflowStep(
                    id="validate",
                    action="Run lab validator",
                    detail="Collect the lab-specific vulnerable and patched verdicts.",
                ),
                WorkflowStep(
                    id="teardown",
                    action="Collect evidence and stop lab",
                    detail="Persist logs and stop only the selected lab.",
                ),
            ],
        )
