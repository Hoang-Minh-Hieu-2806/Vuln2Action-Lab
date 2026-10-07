"""Reproduction executor (SIMULATED in Phase 1; localhost-guarded later).

SAFETY: refuses any non-local target. Real command execution against Docker
labs arrives in Phase 5 and must keep this guard.
"""
from __future__ import annotations

from typing import Any

ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


def is_allowed_target(target: str) -> bool:
    host = (target or "").strip().lower()
    return host in ALLOWED_HOSTS or host in {"lab", "local"}


class ReproductionExecutor:
    """Simulated executor: records what WOULD run without running it."""

    def __init__(self, simulate: bool = True) -> None:
        self.simulate = simulate

    def execute(self, plan: list[dict[str, str]]) -> dict[str, Any]:
        log: list[str] = []
        for step in plan:
            target = step.get("target", "localhost")
            if not is_allowed_target(target):
                raise ValueError(f"Refused non-local target: {target!r}. Labs only.")
            if self.simulate:
                log.append(f"[SIM] {step.get('id')}: {step.get('action')} ({target})")
            else:
                # TODO(Phase 5): run lab-scoped docker commands with timeout.
                raise NotImplementedError("Non-simulated execution lands in Phase 5.")
        return {"simulated": self.simulate, "log": log, "steps": len(plan)}
