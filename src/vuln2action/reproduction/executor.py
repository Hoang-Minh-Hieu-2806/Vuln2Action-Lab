"""Guarded execution boundary for isolated labs."""

from vuln2action.domain import ExecutionPlan, ExecutionResult


def is_allowed_target(target: str, allowed_hosts: set[str] | None = None) -> bool:
    allowed = allowed_hosts or {"localhost", "127.0.0.1", "lab", "local"}
    return (target or "").strip().lower() in {host.lower() for host in allowed}


class ReproductionExecutor:
    """Records simulated runs; real Docker execution remains an explicit later adapter."""

    def __init__(self, simulate: bool = True, allowed_hosts: set[str] | None = None) -> None:
        self.simulate = simulate
        self.allowed_hosts = allowed_hosts

    def execute(self, plan: ExecutionPlan) -> ExecutionResult:
        for step in plan.steps:
            if not is_allowed_target(step.target, self.allowed_hosts):
                raise ValueError(f"Refused non-local target: {step.target!r}. Labs only.")
        if not self.simulate:
            raise NotImplementedError(
                "Real execution is unavailable until a manifest-scoped Docker adapter and "
                "per-lab validator are implemented."
            )
        log = [f"[SIM] {step.id}: {step.action} ({step.target})" for step in plan.steps]
        return ExecutionResult(
            simulated=True,
            completed=True,
            log=log,
            steps_executed=len(plan.steps),
        )
