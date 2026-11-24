# Final Defense Gate report — Vuln2Action-Lab

Scope: evidence-driven demo rehearsal, freeze verification and defense readiness.
No feature development, no retraining, no Kaggle, no Docker.

## A. Preflight

- Timestamp: 2026-11-24T07:57:41Z.
- Branch: `dev`.
- HEAD: `0394b3dd7e5886410eb2004d9806fcd1e6153e09`.
- Staged files: none.
- Modified tracked files: `README.md`, `docs/defense/limitations-slide.md`,
  `docs/paper-deviation-report-vi.md`, `gui/app.py`, `gui/templates/index.html`,
  `reports/execution/finalization-campaign-report.md`, `tests/unit/test_gui.py`.
- Pre-existing untracked entries preserved: `docs/t5-stage1-final-vi.md`,
  `notebooks/kaggle/paper_stage1_target_fp32/resume_cp3465/`,
  `reports/execution/post-kaggle-research-closure-report.md`,
  `scripts/verify_demo_freeze.py`.
- Diff baseline: 7 tracked files, 218 insertions, 56 deletions (warnings LF→CRLF only).
- Existing artifacts inventoried: frozen demo run, 2 screenshots, SHA-256SUMS,
  GUI generation fields (34 references), limitation slide, claims/report docs.
- No source code changed in Phase 0.

## B. Demo freeze verification

- Command: `python scripts/verify_demo_freeze.py`.
- Working directory: repo root `Vuln2Action-Lab`.
- First run: 2026-11-24T07:58:19Z, exit code 0, no stderr.
- Final audit rerun: 2026-11-24T08:02:54Z, exit code 0, no stderr.
- Verdict: `DEMO FREEZE VERDICT: PASS`.
- Expected output from verifier: `provider=rule_based`, `status=SIMULATED`,
  `execution.simulated=true`, `consistency.all_pass=true`, `sha256_entries=14 verified`.
- Demo run ID: `final-cve001-20261123T065251Z`.
- Artifact integrity: 17 files present; two non-empty screenshots;
  `consistency.json` all fields true; `provenance.json` provider `rule_based`,
  `execution_mode=simulated`, `checkpoint_id=null`, integrity content hash
  `cbfa69aa9f0ddd88364d0a9700a759cb68dd46395fc9fb080f2958377a1d5ba3`;
  `report.result.status=SIMULATED`; `validator.status=SIMULATED`.
- No artifact, hash manifest or expected value was modified.

## C. Rehearsal 1

- Report: `reports/defense/rehearsal-01.md`.
- Status: **PARTIAL — AWAITING HUMAN ACTION**.
- Agent-executed safe steps:
  - `vuln2action --list-samples` → exit 0, 3 SAMPLE CVEs listed.
  - `vuln2action --sample CVE-2024-0001 --json-only` → exit 0, 360 lines,
    `provider=rule_based`, `result.status=SIMULATED`, `checkpoint_id=null`.
  - Read frozen retrieval/workflow/validator evidence.
  - Verifier PASS.
- Errors: none in executed portion.
- Duration: 07:59:30Z–07:59:40Z for CLI portion (~10s); full rehearsal not measurable.
- Not executed: Docker `--execute` lab step; visual GUI interaction.
- Outcome: not PASS because not all 7 steps were executed end-to-end.

## D. Rehearsal 2

- Report: `reports/defense/rehearsal-02.md`.
- Status: **AWAITING HUMAN REHEARSAL**.
- Not started because Rehearsal 1 is not complete.
- Human checklist for 7 steps is included in the report.
- No output fabricated; no frozen artifact touched.
- Final rehearsal status: **AWAITING HUMAN ACTION**, not PASS.

## E. Claims consistency

- T5 observed validation: BLEU **0.4802**, ROUGE-L F1 **0.5659**, validation **11,089** rows.
  Source: `data/external/resume_cp3465/.../metrics.json`, kernel log,
  `docs/t5-stage1-final-vi.md`.
- Leakage: **11,083/11,089** overlap preserved as reported; not independently recomputed
  in this gate; source is existing research documentation.
- Demo semantics: verdict `SIMULATED`; GUI flow is `reference_flow`, not T5-generated.
- Claim document: `docs/defense/defense-claims-vi.md`.
- Banned phrase scan over `docs/defense/`, `README.md` and `reports/` found only
  negated forms; no affirmative contradiction required fixing.

## F. Limitations slide

- File: `docs/defense/limitations-slide.md`.
- Required numbers present: BLEU 0.4802, ROUGE-L F1 0.5659, 11,089 samples,
  overlap 11,083.
- Interpretation: observed validation only, no generalization, human eval pending.
- Demonstration: SIMULATED, reference flow, no T5-generated output in demo,
  Docker validation not completed.
- Added a concise `Future work` section: group-based evaluation, human evaluation,
  Docker CI verification.
- Readability: 5 short sections plus evidence pointers; no PowerPoint created
  because no official deck edit was requested.

## G. Checklist

| Checklist item | Evidence | Status | Updated? |
|---|---|---|---|
| `reports/demo-and-defense-checklist.md:49` Full script runs twice consecutively with clean teardown | Rehearsal 01 PARTIAL; Rehearsal 02 AWAITING HUMAN | NOT MET | No |
| Line 50 Every number shown has an artifact file behind it | Claim audit + metrics/demo artifacts; but demo not fully shown | ARTIFACT-BACKED, NOT TICKED | No |
| Line 51 Limitations slide shown before Q&A, not hidden | Slide updated; human must show it | AWAITING HUMAN | No |
| Line 52 Reviewer can answer "What does T5 actually contribute today?" | Q&A doc prepared; reviewer not yet tested | AWAITING HUMAN | No |
| `README.md:88` live labs checkbox | No artifact for cve-002/003 | UNCHANGED / unchecked | No |

No checkbox was ticked prematurely.

## H. Q&A

- File: `docs/defense/anticipated-questions-vi.md`.
- 30/30 required questions prepared across Research, Dataset, Retrieval, T5,
  System, Demo and Future work.
- Answers cite artifacts/source files and avoid exaggeration.
- Remaining knowledge gaps: no independent leakage recomputation artifact in this
  gate; no human rehearsal confirmation; no Docker CI run; full checkpoint weights
  not local.

## I. Tests

| Check | Result |
|---|---|
| `python scripts/verify_demo_freeze.py` | PASS, exit 0, 14 SHA-256 entries |
| `python -m pytest tests/unit/test_gui.py -q` | 10 passed in 1.90s |
| `python -m ruff check .` | All checks passed |
| `python -m ruff format --check .` | 258 files already formatted |
| Docker integration | Not run (out of scope) |
| Kaggle / training | Not run |

No new failures introduced.

## J. Git integrity

- HEAD before: `0394b3dd7e5886410eb2004d9806fcd1e6153e09`.
- HEAD after: `0394b3dd7e5886410eb2004d9806fcd1e6153e09`.
- Branch before/after: `dev`.
- Staged files: none before/after.
- Deletions: none.
- No commit, push, reset, clean, stash, checkout, amend or rebase.
- Modified tracked files: 7 (pre-existing changes preserved).
- Untracked entries: 8, including 4 pre-existing and 4 created in this gate
  (`docs/defense/anticipated-questions-vi.md`, `docs/defense/defense-claims-vi.md`,
  `docs/defense/demo-script-vi.md`, `reports/defense/`).
- Demo artifact not overwritten; verifier still PASS.

## K. Final readiness

| Dimension | Verdict | Basis |
|---|---|---|
| Engineering | READY WITH LIMITATIONS | Verifier, GUI tests, Ruff and format pass; Git intact; generated-flow wiring unavailable by design. |
| Demo | AWAITING HUMAN ACTION | Frozen artifact verified, but two end-to-end human rehearsals are not complete; Docker validation not run. |
| Research | READY WITH LIMITATIONS for observed validation only | Artifact-backed BLEU/ROUGE and leakage statement; not generalization, independent, paper-comparable or full reproduction. |
| Defense | AWAITING HUMAN ACTION | Claims, slide, Q&A and checklist are prepared; human rehearsal and slide presentation remain. |

Overall conclusion: **AWAITING HUMAN ACTION**. This is not "all READY" because the
required human rehearsals have not been performed.

## Files created in this gate

- `docs/defense/anticipated-questions-vi.md`
- `docs/defense/defense-claims-vi.md`
- `docs/defense/demo-script-vi.md`
- `reports/defense/rehearsal-01.md`
- `reports/defense/rehearsal-02.md`
- `reports/execution/final-defense-gate-report.md`

## Files modified in this gate

- `docs/defense/limitations-slide.md`

## Pre-existing changes preserved

- `README.md`, `docs/paper-deviation-report-vi.md`, `gui/app.py`,
  `gui/templates/index.html`, `reports/execution/finalization-campaign-report.md`,
  `tests/unit/test_gui.py`, `docs/t5-stage1-final-vi.md`,
  `notebooks/kaggle/paper_stage1_target_fp32/resume_cp3465/`,
  `reports/execution/post-kaggle-research-closure-report.md`,
  `scripts/verify_demo_freeze.py`.

## Remaining issues

- Human must execute Rehearsal 1 fully and Rehearsal 2 independently.
- Human must show limitations slide before Q&A.
- T3 Human Evaluation, T6 Docker CI, T8 group-split and full checkpoint weights
  remain out of scope/blocked as instructed.
