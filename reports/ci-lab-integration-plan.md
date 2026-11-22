# CI lab integration plan

Status: **PLAN + VERIFIED TESTS** — the CI workflow was not modified. The five
assertions listed below were implemented and executed locally on 2026-11-22;
see `reports/evidence-and-lab-implementation-report.md`.

## Current state (verified)

| Item | Fact | Source |
|---|---|---|
| CI triggers | push `main`, `dev`, `codex/**`; pull_request | `.github/workflows/ci.yml:3-8` |
| Matrix | Ubuntu, Python 3.11 and 3.12 | `ci.yml:13-20` |
| Unit job steps | install, lint, compile, pytest, CLI smoke, retrieval eval, build | `ci.yml:32-60` |
| Docker tests | skipped unless `V2A_DOCKER_TESTS=1` | `tests/integration/test_docker_lab.py:20-23` |
| Live assertions | `simulated is False`, PASS, validation payload PASS | `test_docker_lab.py:26-35` |
| Teardown test | second run up/down idempotent, PASS again | `test_docker_lab.py:38-45` |
| Local result | 248 passed, 6 skipped without opt-in env | `pytest -q` |
| Docker result | 6 passed in 50.58s with `V2A_DOCKER_TESTS=1` | `pytest -q tests/integration/test_docker_lab.py -v` |

**Gap:** CI #6 was green but never built or validated `labs/cve-001`. PASS/FAIL
and evidence are currently only claimed by the source code and local docs.

## Recommended job (separate, opt-in-safe)

```yaml
lab-integration:
  name: Docker lab (cve-001)
  runs-on: ubuntu-latest
  needs: quality
  timeout-minutes: 25
  env:
    V2A_DOCKER_TESTS: "1"
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: "3.11"
        cache: pip
    - run: python -m pip install --upgrade pip
    - run: python -m pip install -e ".[dev]"
    - name: Build and validate localhost lab
      run: python -m pytest -q tests/integration/test_docker_lab.py -v
    - name: Verify no lab containers remain
      if: always()
      run: docker compose -f labs/cve-001/docker-compose.yml down --remove-orphans
```

## Conditions

- Run on PR and push to `dev`; do not run on every external fork PR if Docker
  usage is restricted by the repository owner.
- Keep it a **separate job** so unit-test speed is unaffected.
- Keep the existing skip guard in `test_docker_lab.py`; CI sets the env var
  explicitly rather than removing the guard.
- `needs: quality` avoids burning Docker time on a red unit job.
- `if: always()` teardown prevents orphaned containers on failure.

## Assertions (implemented and locally verified)

1. Evidence schema — `test_live_lab_evidence_schema`: generation input, full
   workflow, plan, `checkpoint_id is None`, PASS payload.
2. Allowlist — `test_live_lab_uses_allowlisted_action_only`: `[workflow]` selection
   line, `validation/labctl.py validate` in the log, and no generated step text
   present in the executed command log.
3. Negative counterfactual — `test_broken_patched_counterfactual_is_not_pass`:
   temporary lab copy whose patched app reflects the marker unescaped; verdict
   must be FAIL with `patched_reflects_escaped is False`.
4. Teardown — `test_live_lab_teardown_removes_containers`: `docker ps` filter on
   `vuln2action-cve-001` returns no container after the run.
5. Localhost guard — `test_executor_refuses_non_local_target_before_running`
   (unit test): non-local target raises before any `subprocess.run` call.

`test_live_lab_produces_a_real_pass` and `test_live_lab_teardown_leaves_no_containers`
remain as the original live-lab checks.

## Cleanup and safety

- Timeout per job and per subprocess already exists (`timeout_seconds=600`).
- Never use `shell=True`; never let generated text become argv.
- Do not disable the vulnerable/patched counterfactual requirement to make CI
  pass.
- Do not mark the Docker job as `continue-on-error`; that would reproduce the
  same "green CI without evidence" problem.

## Why the job is still not enabled

The assertions are implemented and a local Docker run passed (6 tests, 50.58s),
but the CI workflow itself was intentionally left unchanged in this batch. A
GitHub-hosted run must be verified first — Ubuntu runners, Python 3.11/3.12,
fresh images and the `V2A_DOCKER_TESTS=1` env var can behave differently from the
local Windows/Docker Desktop run. Enabling an unverified job risks a permanently
red or misleading CI signal.

Condition to enable: one successful GitHub Actions run of the proposed job on a
push to `dev`, with all six Docker tests passing and no orphaned containers.
