# Post-Kaggle research closure report — Vuln2Action-Lab

Scope: close the T5 Stage 1 experimental record after the Kaggle run, reconcile research
claims, fix GUI flow-data integrity, freeze the existing demo and prepare defense
evidence. No feature expansion beyond this closure.

Safety compliance: no commit/push; no reset/clean/stash; no data deletion; no full model
weight download; no Kaggle rerun or retrain; no dataset/split/benchmark/protocol edit;
no fabricated human evaluation; no generalization claim; no security-boundary change;
no demo artifact overwrite; no Docker integration test.

## 1. T1 artifact verification

Kernel `alexdannguyen/v2a-stage1-resume-checkpoint-3465` is `COMPLETE`. Local artifact
root: `data/external/resume_cp3465/`.

Verified facts:

- Resume path: `global_step=3465 → 4158`; 693 steps = one epoch; completed epoch 6.
- `training_config.json`: `model_name=t5-base`, `target_field=target`,
  `max_input_length=512`, `max_target_length=512`, `per_device_batch_size=8`,
  `gradient_accumulation_steps=4`, `learning_rate=5e-5`, `num_train_epochs=50`,
  `stop_after_epoch=6`, `fp16=false`, `gradient_checkpointing=true`,
  `train_rows=44331`, `validation_rows=11089`,
  `resume_from_checkpoint=/kaggle/input/datasets/alexdannguyen/v2a-stage1-cp3465-1123`.
- `trainer_state.json`: `epoch=6.0`, `global_step=4158`, `best_global_step=4158`,
  `best_metric=0.05401778593659401`, `best_model_checkpoint=.../checkpoint-4158`.
- Kernel log: confirms `--nproc_per_node=2`, `--no-fp16`, `--stop-after-epoch 6`,
  `train_runtime=6121s`, `train_loss=0.498`, final model saved, and
  `EVAL_CKPT: .../checkpoint-4158`.
- `metrics.json`: `rows=11089`, `bleu=0.48018095742031747`,
  `rougeL_f1=0.5659283231713871`, `fp16=false`, `num_beams=4`.
- `predictions.jsonl`: 11,089 lines.
- Full checkpoint weights are **not local**; only `checkpoint-4158/trainer_state.json`
  was downloaded, by design. No fake placeholder was created.

Created `docs/t5-stage1-final-vi.md` with setup, resume history, validation protocol,
results, SHA-256 inventory, missing-artifact list, leakage limitation and claim boundaries.

## 2. T2/T7 research claims

`docs/paper-deviation-report-vi.md` originally had three `PENDING KAGGLE ARTIFACT`
positions. All three were replaced with artifact-backed, scoped statements:

- BLEU 0.4802.
- ROUGE-L F1 0.5659.
- Validation 11,089 rows.
- Resume 3465 → 4158; epoch 6.
- Leakage 11,083 / 11,089 preserved explicitly.
- Claim classes separated: observed validation result = yes; independent evaluation =
  no; generalization evidence = no; paper-comparable result = no.

Two stale epoch-5 lines were also synchronized to epoch 6. Final grep:
`PENDING KAGGLE ARTIFACT` count = 0 in the deviation report. No statement claims
successful paper reproduction or generalization.

Cross-document consistency: `README.md`, `docs/t5-stage1-final-vi.md`,
`docs/paper-deviation-report-vi.md`, `docs/defense/limitations-slide.md` and
`reports/execution/finalization-campaign-report.md` now agree on the Stage 1 result
and its limitation.

## 3. T4 GUI changes and tests

Before the change, `gui/app.py` returned one `flow` key built from the CAPEC catalog.
After the change:

- `reference_flow` holds the CAPEC reference flow.
- `generated_flow` is `None` because no generator/checkpoint is wired into the GUI.
- `generation_status` reports `provider=unavailable`, `status=unavailable` and a reason.
- `flow` remains as a backward-compatible alias of `reference_flow`.
- `build_generation_view()` validates that a `generated` status has a non-empty flow,
  that `simulated` cannot be labelled `generated`, and that `failed` has a reason.
- The template labels the CAPEC flow as reference/not generated and shows generation
  status explicitly; it never labels sample flow as T5 output.

Regression tests in `tests/unit/test_gui.py` cover reference only, generated
successfully, generation failed, not generated, sample flow, T5 unavailable, simulated
vs generated, and invalid generated-without-flow. Result: 10/10 pass.

Real generated-flow wiring remains BLOCKED: no checkpoint/dataset is connected to the
GUI and no fake dataset was created.

## 4. T5 demo freeze

Existing demo `artifacts/demo/final-cve001-20261123T065251Z/` was inspected read-only
and not overwritten.

- 14/14 entries in `hashes/SHA256SUMS.txt` match current files.
- `consistency.json`: `exit_code_zero`, `stderr_empty`, `provider_rule_based`,
  `status_simulated`, `execution_simulated`, `provenance_ref_matches`,
  `report_md_exists`, `provenance_digest_valid`, `all_pass` all true.
- `report.json`: `provider=rule_based`, `result.status=SIMULATED`,
  `execution.simulated=true`, `checkpoint_id=null`.
- `validator/validation.json`: `status=SIMULATED`.
- Two screenshots and all evidence/report/provenance files are present.
- No Docker validation or real PASS/FAIL is claimed.

Created `scripts/verify_demo_freeze.py`, a read-only verifier that prints expected
output and limitations. Current output: `DEMO FREEZE VERDICT: PASS`.

Updated `docs/defense/limitations-slide.md` with the frozen-demo verdict, artifact-backed
Stage 1 observed validation, leakage boundary and GUI reference/generated separation.

## 5. README checklist changes

- `README.md:87` changed from `- [ ]` to `- [x]` for `T5 GPU training run and full evaluation`.
- `README.md:88` remains `- [ ]` for live `cve-002`/`cve-003` labs and generation/reproduction benchmarks.

No other README checkbox was modified.

## 6. Test results

| Check | Result |
|---|---|
| `python -m pytest -q` | 336 passed, 7 skipped in 11.45s |
| `python -m ruff check .` | All checks passed |
| `python -m ruff format --check .` | 252 files already formatted |
| `python -m pytest tests/unit/test_gui.py -q` | 10 passed |
| `python scripts/verify_demo_freeze.py` | PASS, 14 SHA-256 entries verified |
| `python -m py_compile scripts/verify_demo_freeze.py` | OK |

Skipped tests are the existing opt-in Docker tests and the FastAPI test in the global
environment. No Docker integration test was run in this closure.

## 7. SHA-256 inventory

Stage 1 artifacts, computed locally:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `data/external/resume_cp3465/t5_stage1_resume_cp3465/training_config.json` | 959 | `db9a81cd5f2c0f1d2f5870109524948354757ed957ccd3a574c6a39de1fce646` |
| `data/external/resume_cp3465/t5_stage1_resume_cp3465/checkpoint-4158/trainer_state.json` | 17354 | `a8b32cedc690b2bd35731780c79f47902d8277fafcc01a067eb5b61d0f5830d6` |
| `data/external/resume_cp3465/t5_stage1_resume_cp3465_eval_full/metrics.json` | 800 | `0e234ad04434e01c67c954c544fec122a3f59fe2af36fc5e3ca6d244d08f287f` |
| `data/external/resume_cp3465/t5_stage1_resume_cp3465_eval_full/predictions.jsonl` | 42469548 | `c2987c041be4679cd37fb7c83a6a572aaad8f65c196fff520b58b0b30fca21bd` |
| `data/external/resume_cp3465/v2a-stage1-resume-checkpoint-3465.log` | 618782 | `3132381452635cf6b4cab83f01233a1fef966e9e8cd22cb89ba9aef4dd8b6929` |

Demo artifact hashes: `artifacts/demo/final-cve001-20261123T065251Z/hashes/SHA256SUMS.txt`
contains 14 entries; all verified by `scripts/verify_demo_freeze.py`.

## 8. Remaining blockers T3/T8/T6

- T3 Human evaluation: BLOCKED. No authoritative `splits.json`, no 20 generated
  workflows, no advisor review. No scores were fabricated.
- T8 Group-split holdout: PLAN ONLY. No dataset/split edit, no retrain, no group-disjoint
  manifest generated.
- T6 Docker CI: NOT ENABLED. Docker integration tests were not run; no CI job was added.
- Full checkpoint weights (`model.safetensors`, optimizer/scheduler/RNG, final model)
  are not local. Only metadata and log verify checkpoint existence.
- GUI generated-flow wiring remains BLOCKED/unavailable by design; no fake output.
- Independent evaluation and paper-comparable result remain unavailable.

## 9. Git status, diff and untracked files

- HEAD: `0394b3dd7e5886410eb2004d9806fcd1e6153e09`.
- Branch: `dev`.
- No commit, push, reset, clean, stash or checkout was performed.

`git status --short`:

```text
 M README.md
 M docs/defense/limitations-slide.md
 M docs/paper-deviation-report-vi.md
 M gui/app.py
 M gui/templates/index.html
 M reports/execution/finalization-campaign-report.md
 M tests/unit/test_gui.py
?? docs/t5-stage1-final-vi.md
?? notebooks/kaggle/paper_stage1_target_fp32/resume_cp3465/
?? scripts/verify_demo_freeze.py
```

`git diff --stat`: 7 modified files, 218 insertions, 56 deletions. Git emitted harmless
LF→CRLF warnings for three Markdown files; no content was lost.

`notebooks/kaggle/paper_stage1_target_fp32/resume_cp3465/` was already untracked before
this closure and was preserved unchanged. `data/external/resume_cp3465/` is local and
ignored by Git.

## 10. Final readiness

| Dimension | Verdict | Basis |
|---|---|---|
| Engineering | READY WITH LIMITATIONS | Full tests/Ruff/format pass; GUI data fields fixed with regression tests; Docker CI and generated-flow wiring remain out of scope/BLOCKED. |
| Demo | READY WITH KNOWN LIMITATIONS | Frozen artifact verified, 14 hashes match, consistency all_pass, verdict SIMULATED; no Docker PASS claim. |
| Research | PARTIAL — OBSERVED VALIDATION ONLY | Real Stage 1 artifact and observed metrics exist; leakage 11,083/11,089 blocks generalization; no independent eval, human eval or paper-comparable claim. |
| Defense | READY WITH LIMITATIONS | Limitations slide updated; claims and GUI labels are consistent with artifacts; must state SIMULATED demo and leakage before Q&A. |

Final verdict: **closure completed with known limitations**, not a claim of full paper
reproduction or release readiness.

## Created artifacts

- `docs/t5-stage1-final-vi.md`
- `scripts/verify_demo_freeze.py`
- `reports/execution/post-kaggle-research-closure-report.md`

## Modified artifacts

- `README.md`
- `docs/defense/limitations-slide.md`
- `docs/paper-deviation-report-vi.md`
- `gui/app.py`
- `gui/templates/index.html`
- `reports/execution/finalization-campaign-report.md`
- `tests/unit/test_gui.py`

## Preserved pre-existing untracked artifacts

- `notebooks/kaggle/paper_stage1_target_fp32/resume_cp3465/`
- `data/external/resume_cp3465/` (local, Git-ignored)

## Remaining issues

- Full checkpoint weights not downloaded locally.
- T3 human evaluation blocked.
- T8 group-split not implemented.
- T6 Docker CI not enabled.
- GUI generated-flow wiring unavailable.
- No independent or paper-comparable evaluation.
