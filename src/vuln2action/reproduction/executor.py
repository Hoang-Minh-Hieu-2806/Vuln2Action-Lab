"""Guarded execution boundary for isolated labs."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from vuln2action.config import project_root
from vuln2action.domain import ExecutionPlan, ExecutionResult, LabManifest

VALIDATION_PREFIX = "V2A_VALIDATION_JSON:"
_PYTHON_ALIASES = {"python", "python3", "py"}


def is_allowed_target(target: str, allowed_hosts: set[str] | None = None) -> bool:
    allowed = allowed_hosts or {"localhost", "127.0.0.1", "lab", "local"}
    return (target or "").strip().lower() in {host.lower() for host in allowed}


def parse_validation_output(stdout: str) -> dict[str, object] | None:
    """Return the last ``V2A_VALIDATION_JSON:`` payload printed by a lab validator."""
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if not stripped.startswith(VALIDATION_PREFIX):
            continue
        try:
            payload = json.loads(stripped[len(VALIDATION_PREFIX) :])
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None
    return None


class ReproductionExecutor:
    """Runs checked-in, lab-scoped commands; simulated execution stays the default.

    Real execution is deliberately narrow: only commands declared by the lab
    manifest are run, with the lab directory as working directory, no shell, and
    each plan step target must resolve to an allowed local host.
    """

    def __init__(
        self,
        simulate: bool = True,
        allowed_hosts: set[str] | None = None,
        labs_root: str | Path | None = None,
        timeout_seconds: int = 600,
    ) -> None:
        self.simulate = simulate
        self.allowed_hosts = allowed_hosts
        self.labs_root = Path(labs_root) if labs_root is not None else None
        self.timeout_seconds = timeout_seconds

    def execute(
        self,
        plan: ExecutionPlan,
        manifest: LabManifest | None = None,
    ) -> ExecutionResult:
        for step in plan.steps:
            if not is_allowed_target(step.target, self.allowed_hosts):
                raise ValueError(f"Refused non-local target: {step.target!r}. Labs only.")
        if self.simulate:
            log = [f"[SIM] {step.id}: {step.action} ({step.target})" for step in plan.steps]
            return ExecutionResult(
                simulated=True,
                completed=True,
                log=log,
                steps_executed=len(plan.steps),
            )
        return self._execute_real(plan, manifest)

    def _execute_real(
        self,
        plan: ExecutionPlan,
        manifest: LabManifest | None,
    ) -> ExecutionResult:
        if manifest is None:
            raise ValueError("Real execution requires a lab manifest with lab-scoped commands")
        if manifest.lab_id != plan.lab_id:
            raise ValueError(
                f"Manifest lab_id {manifest.lab_id!r} does not match plan lab_id {plan.lab_id!r}"
            )
        if manifest.status == "placeholder":
            raise ValueError(f"Lab {manifest.lab_id!r} is still a placeholder; no commands to run")
        if not manifest.validation_command:
            raise ValueError(f"Lab {manifest.lab_id!r} declares no validation_command")
        if manifest.status == "ready" and not manifest.has_patched_counterfactual:
            raise ValueError(
                f"Lab {manifest.lab_id!r} is marked ready but has no patched counterfactual"
            )

        lab_dir = self._lab_dir(manifest.lab_id)
        log: list[str] = []
        steps_executed = 0
        validation: dict[str, object] | None = None
        error: str | None = None

        try:
            if manifest.setup_command:
                self._run(manifest.setup_command, lab_dir, "setup", log)
                steps_executed += 1
            result = self._run(manifest.validation_command, lab_dir, "validate", log)
            steps_executed += 1
            validation = parse_validation_output(result.stdout)
            if validation is None:
                error = "Lab validator did not emit a V2A_VALIDATION_JSON payload"
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            error = str(exc)
        finally:
            if manifest.teardown_command:
                try:
                    self._run(manifest.teardown_command, lab_dir, "teardown", log)
                    steps_executed += 1
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    log.append(f"[teardown] {exc}")

        completed = validation is not None and validation.get("status") in {"PASS", "FAIL"}
        return ExecutionResult(
            simulated=False,
            completed=completed,
            log=log,
            steps_executed=steps_executed,
            error=error,
            validation=validation,
        )

    def _lab_dir(self, lab_id: str) -> Path:
        root = (self.labs_root or project_root() / "labs").resolve()
        lab_dir = (root / lab_id).resolve()
        if lab_dir == root or root not in lab_dir.parents:
            raise ValueError(f"Lab path escapes the labs root: {lab_id!r}")
        if not lab_dir.is_dir():
            raise FileNotFoundError(f"Lab directory not found: {lab_dir}")
        return lab_dir

    def _run(
        self,
        command: list[str],
        lab_dir: Path,
        label: str,
        log: list[str],
    ) -> subprocess.CompletedProcess[str]:
        argv = [str(part) for part in command if str(part).strip()]
        if not argv:
            raise ValueError(f"Empty {label} command in lab manifest")
        if argv[0] in _PYTHON_ALIASES:
            argv[0] = sys.executable
        log.append(f"[{label}] {' '.join(argv)}")
        result = subprocess.run(
            argv,
            cwd=lab_dir,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        log.append(f"[{label}] exit={result.returncode}")
        if result.returncode != 0 and label != "validate":
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise RuntimeError(f"{label} command failed (exit {result.returncode}): {detail[-1:]}")
        return result
