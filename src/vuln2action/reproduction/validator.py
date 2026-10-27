"""Translate execution evidence into a truthful verdict."""

from vuln2action.domain import ExecutionResult, ReproductionResult, ReproductionStatus


class Validator:
    def validate(self, cve_id: str, lab_id: str, execution: ExecutionResult) -> ReproductionResult:
        if execution.simulated:
            return ReproductionResult(
                cve_id=cve_id,
                lab_id=lab_id,
                status=ReproductionStatus.SIMULATED,
                steps_executed=execution.steps_executed,
                details="Plan was simulated; no vulnerability claim was validated.",
                evidence={"execution_log": execution.log},
            )
        if execution.error:
            return ReproductionResult(
                cve_id=cve_id,
                lab_id=lab_id,
                status=ReproductionStatus.ERROR,
                steps_executed=execution.steps_executed,
                details=execution.error,
                evidence={"execution_log": execution.log},
            )
        validation = execution.validation or {}
        verdict = validation.get("status")
        evidence = {"execution_log": execution.log, "validation": validation}
        if verdict == "PASS":
            return ReproductionResult(
                cve_id=cve_id,
                lab_id=lab_id,
                status=ReproductionStatus.PASS,
                steps_executed=execution.steps_executed,
                details="Lab validator confirmed the vulnerable and patched counterfactuals.",
                evidence=evidence,
            )
        if verdict == "FAIL":
            return ReproductionResult(
                cve_id=cve_id,
                lab_id=lab_id,
                status=ReproductionStatus.FAIL,
                steps_executed=execution.steps_executed,
                details="Lab validator ran, but the counterfactual check did not hold.",
                evidence=evidence,
            )
        if verdict == "ERROR":
            return ReproductionResult(
                cve_id=cve_id,
                lab_id=lab_id,
                status=ReproductionStatus.ERROR,
                steps_executed=execution.steps_executed,
                details=str(validation.get("checks", "Lab validator reported an error.")),
                evidence=evidence,
            )
        return ReproductionResult(
            cve_id=cve_id,
            lab_id=lab_id,
            status=ReproductionStatus.SKIPPED,
            steps_executed=execution.steps_executed,
            details="No lab-specific vulnerable/patched validator supplied a verdict.",
            evidence=evidence,
        )
