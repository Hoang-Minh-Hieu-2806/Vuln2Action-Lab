# Evidence provenance + Docker lab assertions — implementation report

Date: 2026-11-22. Branch: `dev`. HEAD before and after: `4283360`.
No commit, no push, no Kaggle kernel interaction, no training, no GUI changes,
no benchmark changes, no fabricated human-evaluation data.

## Files changed (tracked source and tests)

| File | Change |
|---|---|
| `src/vuln2action/domain/workflow.py` | added `Workflow.checkpoint_id: str | None = None` |
| `src/vuln2action/domain/evidence.py` | added `EvidenceBundle.checkpoint_id: str | None = None` |
| `src/vuln2action/generation/t5.py` | `flow_to_workflow(..., checkpoint_id=None)` writes the field; `T5Generator.generate` passes `flow.checkpoint` |
| `src/vuln2action/evidence/collector.py` | added `add_checkpoint_id()` |
| `src/vuln2action/pipeline/run.py` | copies `workflow.checkpoint_id` into evidence |
| `tests/unit/test_evidence_provenance.py` | new, 6 tests |
| `tests/unit/test_executor.py` | added non-local target guard test |
| `tests/integration/test_docker_lab.py` | added 4 Docker assertions + imports |
| `reports/ci-lab-integration-plan.md` | updated with verified local results and enable condition |

Diff stat for tracked source/tests at the end: 7 files, 141 insertions, 1 deletion
(excluding the report files created in the previous batch, which remain untracked).

## Where the checkpoint metadata was dropped

`T5Generator.generate_flow` returns `GeneratedFlow(text, checkpoint=self.checkpoint,
steps=...)` (`generation/t5.py:296`). `flow_to_workflow` built a `Workflow` from
the text but never accepted or copied the checkpoint, so the evidence bundle
could not say which weights produced a workflow. The fix carries it through the
real path: `GeneratedFlow.checkpoint` -> `flow_to_workflow(checkpoint_id=...)` ->
`Workflow.checkpoint_id` -> `EvidenceBundle.checkpoint_id`.

## Schema change and backward compatibility

- Two optional fields with default `None`; no required field was added.
- No schema-version field was introduced: additive optional fields with Pydantic
  defaults keep old JSON artifacts loadable, and a version bump would add churn
  without changing interpretation.
- No `model_revision` field was added: no real source provides it, and the task
  forbids guessing metadata.
- Rule-based runs have no checkpoint; `checkpoint_id` stays `None` and the
  pipeline succeeds.
- Old evidence dicts without the field load with `checkpoint_id is None`
  (verified by test).

## Tests added

| Test | Purpose |
|---|---|
| `test_evidence_keeps_checkpoint_metadata` | new evidence keeps checkpoint id |
| `test_old_evidence_without_checkpoint_loads` | old artifact remains loadable |
| `test_flow_to_workflow_keeps_checkpoint` | transform does not drop metadata |
| `test_t5_generate_carries_checkpoint_into_workflow` | real generator path with injected fake model |
| `test_serialization_roundtrip_keeps_checkpoint` | Workflow and EvidenceBundle JSON round trip |
| `test_pipeline_without_checkpoint_does_not_fail` | rule-based pipeline stays SIMULATED with `None` |
| `test_executor_refuses_non_local_target_before_running` | localhost guard before any subprocess |
| `test_live_lab_evidence_schema` | Docker evidence schema assertion |
| `test_live_lab_uses_allowlisted_action_only` | workflow selects allowlist key; generated text not argv |
| `test_live_lab_teardown_removes_containers` | no lab containers after run |
| `test_broken_patched_counterfactual_is_not_pass` | negative counterfactual yields FAIL |

The existing `test_live_lab_produces_a_real_pass` and
`test_live_lab_teardown_leaves_no_containers` were kept unchanged.

## Tests executed and actual results

| Command | Result |
|---|---|
| `python -m ruff check src api scripts tests evaluation gui` | All checks passed, exit 0 |
| `python -m ruff format --check src api scripts tests evaluation gui` | initially 2 files unformatted; fixed with `ruff format` on those files; final check 145 files already formatted |
| `python -m pytest -q` | **248 passed, 6 skipped**, exit 0 |
| `$env:V2A_DOCKER_TESTS='1'; python -m pytest -q tests/integration/test_docker_lab.py -v` | **6 passed in 50.58s**, exit 0 |

The 6 skipped unit-job tests are the opt-in Docker tests; they are skipped
because the environment variable is absent, not because of a failure.

## Assertions NOT evaluated

- **GitHub-hosted CI**: the proposed `lab-integration` job was not added to
  `.github/workflows/ci.yml` and no GitHub run was triggered. Ubuntu runner
  behaviour is therefore NOT EVALUATED.
- **Stage-1 / stage-2 training**: NOT EVALUATED; Kaggle kernel untouched.
- **GUI generated flow**: NOT EVALUATED; depends on the checkpoint.
- **Python 3.11/3.12 clean container re-run after this batch**: NOT EVALUATED;
  only local Python 3.13 and the earlier Docker 3.11 baseline were used.

## Safety properties preserved

- Validator logic was not changed; the negative test edits only a temporary copy
  of the target app outside the repository.
- Manifest remains the only source of executable argv; the workflow chooses an
  allowlist key and is logged as provenance.
- No `shell=True`; generated step text is asserted absent from the command log.
- Executor refuses non-local targets before any subprocess call.
- `cve-002`/`cve-003` remain placeholders.

## Remaining risks

- The Docker run passed on Windows/Docker Desktop only; CI enablement still
  needs a green GitHub-hosted run.
- The negative counterfactual depends on Docker image rebuild time and fixed
  host ports; parallel lab jobs would collide.
- `checkpoint_id` records the checkpoint string, not a verified weight hash;
  a stronger provenance link would need a model artifact digest.
- Adding optional fields changes public Pydantic schemas; downstream consumers
  that regenerate strict schemas should be checked before release.

## Status

Part A: **DONE** — schema change, tests and verification evidence present.
Part B: **DONE locally** — five assertions implemented; six Docker tests passed.
Part C: **PARTIALLY DONE** — CI plan updated; job deliberately not enabled.
