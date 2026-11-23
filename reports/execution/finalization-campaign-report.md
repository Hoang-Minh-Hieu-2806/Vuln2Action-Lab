# Finalization campaign report

Date: 2026-11-23. Branch `dev`, HEAD `886c17c`. No commit, push, reset, clean,
stash or branch switch during this campaign. All pre-existing changes preserved.

## A. Preflight

- Git baseline: `dev...origin/dev`, HEAD `886c17c5a2639456b8ab19b55662fe658e815407`.
  Working tree at start: `M .gitignore` only (from the previous hygiene request).
- Read: `README.md`, `reports/execution/post-kaggle-roadmap.md`,
  `docs/paper-deviation-report-vi.md`, `reports/execution/pony-tail-optimization-report.md`.
- Python 3.13.2 local; Ruff 0.17.3; credential helper is `manager-core` from the
  user's global `C:/Users/HOANG MINH HIEU/.gitconfig` (not modified).
- No Kaggle interaction and no Docker lab execution in this campaign.

## B. Demo freeze

- **Run ID:** `final-cve001-20261123T065251Z`
- **Artifact directory:** `artifacts/demo/final-cve001-20261123T065251Z/`
  (new directory; `artifacts/demo/cve-001/` untouched).
- **Command:** `vuln2action --sample CVE-2024-0001 --provider rule_based --save <run_id>`
  (simulation only; `--execute` deliberately not used).
- **Exit code:** `0`. stderr: empty. Verdict: `SIMULATED`.
- Collected: `workflow/workflow.json`, `workflow/plan.json`,
  `validator/validation.json`, `execution/execution.json`, `evidence/evidence.json`,
  `evidence/report.json`, `evidence/report.md`, `evidence/provenance.json`,
  input snapshots, stdout/stderr/exit logs, consistency check, screenshots and hashes.
- **Screenshots:** `screenshots/cli-console.png` (1400x2312),
  `screenshots/report-md.png` (1400x170). Generated from real console/report text.
- **Consistency:** `consistency.json` — all checks `true`: exit 0, empty stderr,
  CVE id, rule_based provider, SIMULATED status, simulated execution, provenance
  ref match, report.md present, provenance digest valid.
- **SHA-256:** full list in `hashes/SHA256SUMS.txt` (14 files). Key hashes:
  - `103a6cb4...` `logs/cli-stdout.log`
  - `33c83600...` `evidence/report.json`
  - `3325ed7c...` `evidence/report.md`
  - `b1952730...` `evidence/provenance.json`
  - `c7550ab3...` `screenshots/cli-console.png`
- **BLOCKED:** real Docker validation. No live lab was run, so this demo proves
  the simulated path only; no PASS/FAIL claim is made.

## C. Research claims audit (T2)

| Claim / checkbox | Status | Evidence |
|---|---|---|
| Package, CLI, domain contracts, lab manifests | VERIFIED | README 62-63; CI run #10 success; 327 local tests pass |
| Generation abstraction (rule_based/t5/LLM stub) | VERIFIED | `src/vuln2action/generation`; provider tests; README 64-65 |
| Retrieval backends + tracked benchmark | VERIFIED | `evaluation/datasets/retrieval_benchmark.json`; semantic P@3=0.296296, MRR@3=0.777778 |
| CAPEC selection 87/100, independent caveat | PARTIALLY VERIFIED | `docs/capec-selection-report-vi.md`, benchmark files; not recomputed this campaign |
| Dataset 44,331 train / 11,089 validation | PARTIALLY VERIFIED | docs/manifests describe counts; generated dataset files absent locally |
| T5 GPU training run and full evaluation | PENDING / BLOCKED | README 87 unchecked; Kaggle last observed `RUNNING`, no `metrics.json`; no new Kaggle interaction |
| BLEU/ROUGE final numbers | NOT CLAIMED | `docs/paper-deviation-report-vi.md:119` still `PENDING KAGGLE ARTIFACT`; no metrics artifact found |
| Live labs `cve-002`/`cve-003` | BLOCKED | README 88 unchecked; Docker execution out of scope |
| Real `PASS`/`FAIL` for `cve-001` | PARTIALLY VERIFIED | historical live-lab artifacts exist; this campaign ran simulation only |
| Hybrid / CVE-only / gold-CAPEC separation | VERIFIED as policy | `docs/t5-group-split-plan.md` and deviation report require separate reporting |
| Human evaluation (3 experts / Table 6) | NOT CLAIMED | single advisor protocol; no scores; no external contact |

README checkboxes were **not** changed: the two unchecked items remain unchecked
because no corresponding artifact exists.

## D. API/GUI verification

- Isolated venv: `C:\Users\HOANGM~1\AppData\Local\Temp\opencode\v2a-final-venv`
  (global Python untouched).
- Installed declared extras: `.[api,gui,dev]` → FastAPI 0.165.0, Flask 3.1.3, uvicorn, pytest.
- API startup: `Vuln2Action-Lab 8`, exit 0.
- Local-only uvicorn `127.0.0.1:8765`; results:
  - `/openapi.json` 200
  - `/docs` 200
  - `/cve` 200
  - `/cve/CVE-2024-0001` 200
- Server terminated after smoke; no public bind.
- GUI startup: **BLOCKED** — `data/processed/reproduction/cves.jsonl` absent. The
  failure is actionable (`create_app()` raises a RuntimeError with build instructions),
  matching `test_gui_fresh_clone.py`. No fake dataset was created.
- CLI regression in venv: exit 0, verdict `SIMULATED`.
- Detailed machine-readable results: temp file `v2a-final-verify/api-gui-cli-results.json`
  (outside the repository).

## E. T3 human evaluation preparation

Existing package: `protocol.md`, `reviewer-form.md`, `cases.json`, `README.md`.
New file: `docs/human-evaluation/sampling-and-data-format.md` with:
- authoritative sampling from `splits.json["human_eval_20"]`, not hand-picked cases;
- JSONL schema with empty/null scores (no fabricated values);
- advisor instructions and safety rules;
- explicit BLOCKER: no `splits.json`, no advisor, no final T5 workflows.

`docs/human-evaluation/README.md` now lists the new file. No score was created.

## F. T8 group split preparation

`docs/evaluation/t5-group-split-plan.md` already existed with grouping key,
near-duplicate union-find, group-disjoint assertions and scope boundaries. Added a
**Metrics to report** section: leakage counts, group-disjoint assertions, BLEU/ROUGE,
exact-target match rate, distinct-target coverage, reproducibility hashes and a
one-shot test-set decision rule. No dataset, benchmark, split manifest or training
configuration was changed.

## G. Repository hygiene

- `.gitignore` already had `.playwright-cli/` added before this campaign; preserved.
  `graphify-out/` was already ignored.
- `.github/workflows/ci.yml`: pinned Ruff with `python -m pip install ruff==0.17.3`
  after `pip install -e ".[dev]"` to stop formatter-version drift.
- `reports/execution/pony-tail-optimization-report.md`: appended verified CI
  follow-up for commits `7bece23` and `886c17c`, including Docker 3.11/3.12 proof
  and GitHub Actions run #10 success.
- Credential helper warning: `manager-core` is configured in the user's global
  git config; not modified (external user configuration).
- No user data or historical evidence deleted.

## H. Test results

| Check | Result |
|---|---|
| `python -m pytest -q -rs` | 327 passed, 7 skipped |
| Skips | 6 Docker opt-in + 1 FastAPI missing in global env (API verified in venv instead) |
| `python -m ruff check src api scripts tests evaluation` | All checks passed |
| `python -m ruff format --check src api scripts tests evaluation` | 155 files already formatted |
| CI run #10 (`886c17c`) | success on Python 3.11 and 3.12 |
| Docker Python 3.11 / 3.12 local reproduction | 311 passed, 22 skipped each |
| Demo consistency | all checks true |

## Blockers

1. Kaggle final artifact/metrics unavailable; no BLEU/ROUGE computed or invented.
2. Docker lab validation not executed (explicit constraint); demo is simulated only.
3. GUI full startup blocked by missing `data/processed/reproduction`.
4. Human evaluation blocked by missing `splits.json` and no advisor contact.
5. `credential-manager-core` warning remains in global git config (not touched).

## Git diff at end

Modified: `.github/workflows/ci.yml`, `.gitignore`,
`docs/evaluation/t5-group-split-plan.md`, `docs/human-evaluation/README.md`,
`reports/execution/pony-tail-optimization-report.md`.
New: `artifacts/demo/final-cve001-20261123T065251Z/`,
`docs/human-evaluation/sampling-and-data-format.md`, this report.
No commit or push.

## Readiness conclusions (kept separate)

1. **Engineering readiness: READY.** CI green, Ruff/format clean, 327 tests pass,
   audit/security/evidence fixes verified. Remaining items are hygiene/blockers,
   not correctness regressions.
2. **Demo readiness: READY WITH KNOWN LIMITATIONS.** CLI + evidence + provenance +
   API localhost smoke work. GUI needs a dataset; Docker labs are not run; all
   generated verdicts in this campaign are clearly `SIMULATED`.
3. **Research readiness: NOT READY.** Final Kaggle metrics, full evaluation, human
   evaluation and group-split execution are absent. BLEU/ROUGE remain `PENDING`.
4. **Defense readiness: READY WITH LIMITATIONS if honesty is kept.** The repo can
   defend the engineering and caveated negative-result story, but must not claim
   full paper reproduction, three-expert human evaluation, 50 epochs, or T5
   fine-tuned effectiveness without artifacts.
