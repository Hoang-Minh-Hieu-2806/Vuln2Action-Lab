"""Validator: decide PASS/FAIL for a reproduction run."""
from __future__ import annotations

from typing import Any

from src.reproduction.result import ReproductionResult, ReproductionStatus


class Validator:
    """Phase 1 stub: PASS when simulated execution covered >=1 step.

    TODO(Phase 6): per-lab validation scripts with strict criteria.
    """

    def validate(self, cve_id: str, lab_id: str, exec_info: dict[str, Any]) -> ReproductionResult:
        steps = int(exec_info.get("steps", 0))
        if steps > 0:
            return ReproductionResult(
                cve_id=cve_id, lab_id=lab_id, status=ReproductionStatus.PASS,
                steps_executed=steps,
                details="Simulated run completed all planned steps (Phase 1 stub).",
                evidence={"execution_log": exec_info.get("log", [])},
            )
        return ReproductionResult(
            cve_id=cve_id, lab_id=lab_id, status=ReproductionStatus.FAIL,
            steps_executed=0, details="No steps executed.",
        )
