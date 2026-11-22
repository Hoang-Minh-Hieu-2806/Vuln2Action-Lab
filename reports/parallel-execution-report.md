# Parallel execution report

Date: 2026-11-22. Scope: work executable while the Kaggle stage-1 kernel runs.
No source code was modified and no commit/push was made in this session.

## 1. Repository identity

| Item | Value |
|---|---|
| Branch | `dev` |
| HEAD | `42833606ea5acba221c6289d8439201a59d7921c` |
| Tracking | `dev...origin/dev` |

## 2. Git status

- Before: clean (`git status --short` produced no output).
- After: only new untracked paths from this session:
  - `?? docs/evaluation/`
  - `?? docs/human-evaluation/`
  - `?? docs/paper-deviation-report-vi.md`
  - `?? reports/`

No tracked file was changed. No commit, no push, no branch switch, no reset,
no stash, no clean.

Two path typos created stray directories outside the repository; both were
removed and the final check found 0 directories containing `&&` on the Desktop.

## 3. Task status

| Task | Status | Reason |
|---|---|---|
| 0 Baseline audit | DONE | `reports/parallel-work-baseline-audit.md` |
| 1 Human evaluation | PARTIALLY DONE | package created; not sendable until split + workflows exist |
| 2 CAPEC freeze / group split | PARTIALLY DONE | freeze record complete; group split is plan only |
| 3 T5 -> pipeline -> evidence audit | DONE | `reports/t5-pipeline-evidence-audit.md` |
| 4 Paper deviation draft | DONE | `docs/paper-deviation-report-vi.md`, Kaggle numbers placeholder |
| 5 CI lab integration plan | PARTIALLY DONE | plan only; CI not modified |
| 6 GUI preparation | PARTIALLY DONE | audit + contract only; no UI code changed |

No task was marked DONE merely because a file was created: each DONE item has
verified source references or a hash in the file.

## 4. Files created

| File | Purpose |
|---|---|
| `reports/parallel-work-baseline-audit.md` | repository state, gaps, task split |
| `reports/t5-pipeline-evidence-audit.md` | required component table with severity |
| `reports/ci-lab-integration-plan.md` | separate Docker job + assertions to add |
| `reports/gui-generation-preparation.md` | data contract and no-checkpoint state |
| `docs/human-evaluation/cases.json` | 20 candidate CVE ids with provenance |
| `docs/human-evaluation/protocol.md` | rubric, flags, aggregation, safety |
| `docs/human-evaluation/reviewer-form.md` | one block per case, separated reference |
| `docs/human-evaluation/README.md` | why it is not sendable yet |
| `docs/evaluation/capec-independent-freeze.md` | SHA-256, protocol, metrics, limits |
| `docs/evaluation/t5-group-split-plan.md` | leakage fix protocol, not executed |
| `docs/paper-deviation-report-vi.md` | draft with `PENDING KAGGLE ARTIFACT` |

Files modified: none.

## 5. Tests run in this session

| Command | Result |
|---|---|
| `python -m pytest -q` from repo root | 241 passed, 2 skipped, exit 0 |
| `python -m ruff check src api scripts tests evaluation gui` | All checks passed, exit 0 |
| JSON parse of `docs/human-evaluation/cases.json` | 20 ids, exit 0 |
| `Get-FileHash evaluation/datasets/capec_independent.json -Algorithm SHA256` | `93128e50...49c8`, matches freeze record |

One earlier `pytest` attempt was run from a temp directory and collected stray
copies under `Temp/opencode/v2a-ci/`, producing an `ImportPathMismatchError`.
That was a working-directory mistake, not a repository failure; the re-run from
the repo root is the valid result above.

## 6. Tests not run

- `V2A_DOCKER_TESTS=1` Docker integration (needs live Docker lab run).
- GitHub Actions rerun (CI #6 is historical evidence, not re-triggered here).
- Stage-1 or Stage-2 training/evaluation — explicitly forbidden in this phase.
- SBERT experiments.

## 7. Blocked by Kaggle

- Real T5-generated flow in GUI.
- Final stage-1 BLEU/ROUGE and README `T5 GPU training run` checkbox.
- Stage 2 CVE-only.
- The `generated_flow` view needs the checkpoint from
  `phamquang0606/vuln2action-paper-stage1-cve-only-target-fp32`; no artifact was
  downloaded, no kernel version was pushed, and no run was cancelled.

## 8. Waiting on the advisor

Human evaluation can be sent only after:
1. `splits.json["human_eval_20"]` is obtained from the dataset owner.
2. The 20 workflows are generated with a recorded checkpoint.
3. Dataset SHA-256 and checkpoint id are filled into the form header.

No score was pre-filled and no case was fabricated. The source list in
`cases.json` is marked `candidate-list-unverified-against-local-split`.

## 9. Important technical findings

- Evidence now stores generation input/output, workflow and plan, but **not a
  checkpoint/model id**; `GeneratedFlow.checkpoint` is dropped by
  `flow_to_workflow` (`generation/t5.py:296`, `:304`).
- GUI has one `flow` field built from the CAPEC reference (`gui/app.py:56`,
  `:147`); there is no `reference_flow` / `generated_flow` split.
- Both `cve-001` allowlisted actions call the same fixed-marker validator; the
  workflow only selects which allowlisted key is logged.
- CI does not exercise Docker integration: `test_docker_lab.py` is skipped unless
  `V2A_DOCKER_TESTS=1`.
- Independent CAPEC benchmark is frozen at SHA-256 `93128e50...49c8`; its
  12/21 coverage ceiling is a structural limit, not a ranker defect.
- 11,083/11,089 stage-1 validation targets already appear in training; BLEU on
  that split is not generalisation.

## 10. Remaining risks

- If the advisor is engaged only after the Kaggle run finishes, human evaluation
  becomes the schedule bottleneck.
- Adding a checkpoint id to evidence changes a public Pydantic schema; needs a
  decision and a compatibility check before implementation.
- Making the validator consume a workflow-derived marker is a larger change and
  must preserve manifest-only argv plus vulnerable/patched counterfactuals.
- No fresh holdout exists for generation; the current validation split was also
  used for decoding tuning.

## 11. Next actions

1. When the Kaggle kernel ends, download `metrics.json`, `predictions.jsonl` and
   the checkpoint; fill the `PENDING KAGGLE ARTIFACT` placeholder.
2. Obtain `splits.json`, replace the candidate case list, generate the 20
   workflows and send the human-evaluation form to the advisor.
3. Decide whether to add checkpoint metadata to `EvidenceBundle`.
4. After the checkpoint exists, add the `reference_flow` / `generated_flow`
   separation in the GUI with tests.
5. Add the Docker CI job only after the assertions in the plan are implemented
   and a live local lab run passes.
