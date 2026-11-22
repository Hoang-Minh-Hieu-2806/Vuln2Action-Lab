# Parallel work baseline audit

Date: 2026-11-22. Scope: read-only audit for the tasks that can proceed while the
Kaggle stage-1 run is in progress. No source file was modified in this phase.

## Repository state

| Item | Value | Evidence |
|---|---|---|
| Branch | `dev` | `git status --short --branch` |
| HEAD | `42833606ea5acba221c6289d8439201a59d7921c` | `git rev-parse HEAD` |
| Tracking | `dev...origin/dev`, up to date | `git status` |
| Working tree | clean before this phase | `git status --short` produced no output |
| Recent commits | `cea1892` (torch-free tests), `4283360` (allowlisted workflow actions) | `git log --oneline -4` |

The baseline SHA stated in the task description matches the observed HEAD.

## Existing implementations (verified in source)

| Area | Implementation | Source |
|---|---|---|
| Typed contracts | Pydantic models with `extra="forbid"` | `src/vuln2action/domain/*.py` |
| NVD / MITRE / ExploitDB connectors | opt-in parsers, no network in pipeline | `src/vuln2action/connectors/` |
| Paper dataset builder | `PAPER_HUMAN_EVAL_CVES`, deterministic `make_splits` | `src/vuln2action/connectors/reproduction.py:35`, `:222` |
| Retrieval | keyword / TF-IDF / semantic backends + ranker | `src/vuln2action/retrieval/` |
| CAPEC mapping | TF-IDF and Word2Vec candidate ranking | `src/vuln2action/retrieval/capec.py` |
| Generation | provider interface, rule-based, T5 adapter | `src/vuln2action/generation/` |
| Pipeline | `analyze_cve` -> workflow -> plan -> executor -> validator -> evidence | `src/vuln2action/pipeline/analyze.py`, `run.py` |
| T5 config | `checkpoint: ""`, `device: cpu`, `base_checkpoint: t5-small` | `config/models.yaml:21-31` |
| Guardrails | localhost allowlist, manifest-only argv, no shell | `src/vuln2action/reproduction/executor.py` |
| Lab `cve-001` | vulnerable + patched + fixed-marker validator + allowlist actions | `labs/cve-001/` |
| GUI | Flask, read-only, `_flow_view()` reads reference CAPEC flow | `gui/app.py:56`, `:147` |
| API | scaffold only | `api/` |
| CI | pushes to `main`, `dev`, `codex/**`; PR; Python 3.11/3.12 | `.github/workflows/ci.yml` |

## Tests and reproduction evidence from prior verified runs

These were run in earlier sessions on this repository; they are recorded here as
historical evidence, not re-executed during Phase 0.

| Check | Result | Notes |
|---|---|---|
| Local `pytest -q` | 241 passed, 2 skipped | 2 Docker integration tests require `V2A_DOCKER_TESTS=1` |
| Docker `python:3.11-slim`, clean `git archive` snapshot | 226 passed, 16 skipped | optional extras not installed |
| Ruff check / format / compileall / CLI smoke / retrieval / build | all exit 0 | CI-equivalent steps |
| GitHub Actions run #6 (`4283360`) | success | Python 3.11 and 3.12 |

## Local artifacts

| Path | State |
|---|---|
| `data/processed/reproduction/` | absent on this machine |
| `data/raw/capec/capec_latest.xml`, `data/raw/cwe/cwec_latest.xml` | present locally, git-ignored |
| `models/t5-capec-flows/` | present locally, git-ignored |
| `results/evaluation/` | present locally, git-ignored |
| `evaluation/datasets/capec_independent.json` | tracked, 21 cases |
| `evaluation/datasets/capec_benchmark.json` | tracked, 120 cases, circular labels |

## Gaps that block "done"

1. No Kaggle stage-1 metrics or checkpoint artifact in the repository or local
   dataset yet; the kernel is still running on account `phamquang0606`.
2. GUI has no `generated_flow` view and no checkpoint metadata display.
3. Evidence records generation input/output, workflow and plan, but not a
   checkpoint/model identifier or reference-vs-generated provenance.
4. The two `cve-001` allowlisted actions call the same validator with a fixed
   marker; provenance is captured, but the generated workflow does not change
   the validation payload.
5. CI does not exercise Docker integration; PASS/FAIL and evidence are not
   automatically verified.
6. Human evaluation package is absent; only the CVE id list exists in source.
7. Independent CAPEC benchmark has no frozen version record or hash document.
8. Stage-1 validation split has 11,083/11,089 target overlap with training data,
   so its BLEU is not a generalisation measure.

## Work possible without the Kaggle checkpoint

- Human evaluation protocol, form and case manifest (Task 1).
- Independent CAPEC benchmark freeze and group-split protocol (Task 2).
- T5 provider -> pipeline -> evidence source audit (Task 3).
- Paper deviation draft with `PENDING KAGGLE ARTIFACT` placeholders (Task 4).
- CI lab integration plan (Task 5).
- GUI data-plumbing audit; no simulated T5 output (Task 6).

## Work that must wait for the checkpoint

- Wiring a real T5-generated flow into the GUI.
- Final stage-1 BLEU/ROUGE values and README status update.
- Stage 2 CVE-only training/evaluation.
