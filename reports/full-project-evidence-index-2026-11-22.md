# Audit evidence index — 2026-11-22

## Fresh commands executed in this audit (read-only)

| Command | Result | Used for |
|---|---|---|
| `git status --short --branch` | `dev...origin/dev`, 7 modified tracked files, 5 untracked paths | working tree state |
| `git rev-parse HEAD` | `42833606ea5acba221c6289d8439201a59d7921c` | baseline identity |
| `git log --oneline -5` | `4283360`, `cea1892`, `78edf05`, `3bac40b`, `4420559` | recent history |
| `git ls-files data models results reports` | only `.gitkeep` + 3 sample JSON | dataset artifact absence |
| `Test-Path data/processed/reproduction` | False | paper dataset NOT VERIFIED locally |
| `Test-Path data/raw/cwe`, `data/raw/capec` | True | retrieval environment difference |
| `Test-Path models/t5-capec-flows/training_summary.json` | True | local toy T5 artifact |
| `Get-Content models/t5-capec-flows/training_summary.json` | t5-small, 120 steps, 148 train records | not the paper stage-1 run |
| `python -m ruff check src api scripts tests evaluation gui` | exit 0 | CI-scope lint |
| `python -m ruff check . --output-format concise` | exit 1, 5 errors in `labs/` | full-scope lint finding |
| `python -m compileall -q src/vuln2action api scripts tests evaluation` | exit 0 | compile check |
| `python -m pytest -q` | 248 passed, 6 skipped, exit 0 | unit/integration (Docker opt-in skipped) |
| `Get-Content labs/cve-00{1,2,3}/lab.yaml` | ready / placeholder / placeholder | lab status |
| `Select-String README.md '^- \[[ x]\]'` | 17 checked, 2 unchecked | documentation claim check |

## Source symbols inspected

| Path | Symbol | Finding |
|---|---|---|
| `src/vuln2action/domain/workflow.py:27` | `Workflow` | `extra="forbid"`, `checkpoint_id` added |
| `src/vuln2action/domain/evidence.py:16` | `EvidenceBundle` | `extra="forbid"`, `checkpoint_id` added |
| `src/vuln2action/generation/t5.py:71,144,204,274,296-307` | `GeneratedFlow`, `flow_to_workflow`, `T5Generator` | checkpoint carried from `GeneratedFlow` into `Workflow` |
| `src/vuln2action/generation/base.py:17` | `get_generator` | provider `enabled` flag ignored |
| `src/vuln2action/generation/llm.py:10` | `LLMGenerator` | stub |
| `src/vuln2action/generation/parser.py:11` | `parse_workflow` | strict `model_validate` |
| `src/vuln2action/retrieval/semantic.py:236-240` | `load_semantic_enricher` | reads raw MITRE XML when present |
| `src/vuln2action/reproduction/executor.py:21-31,108-124` | `select_validation_command`, `_execute_real` | manifest-only argv |
| `src/vuln2action/reproduction/planner.py:7` | `ReproductionPlanner.plan` | workflow → plan |
| `src/vuln2action/reproduction/validator.py:7` | `Validator.validate` | verdict mapping |
| `labs/cve-001/validation/labctl.py:31-32,109-139` | `MARKER`, `command_validate` | fixed marker, counterfactual |
| `labs/cve-001/target/app.py` | `Handler.do_GET` | vulnerable escapes only in patched mode |
| `gui/app.py:56,110-150` | `_flow_view`, `analyze` | reference CAPEC flow only |
| `api/routes/analysis.py:20` | `analyze` | `model_dump` response |
| `api/routes/results.py:19-25` | `read_result` | raw `report.json` |
| `src/vuln2action/cli.py:64-65` | CLI JSON output | full `PipelineResult` dump |
| `.github/workflows/ci.yml:3-8,32-60` | CI trigger and steps | dev trigger; no Docker job |

## Tests cited (some historical, explicitly marked)

| Test | Status |
|---|---|
| `tests/unit/test_evidence_provenance.py` (6 tests) | present; executed in fresh `pytest` (pass) |
| `tests/unit/test_executor.py` guard test | present; executed fresh (pass) |
| `tests/integration/test_docker_lab.py` (6 tests) | skipped in fresh audit run; historical batch: 6 passed in 50,58s with `V2A_DOCKER_TESTS=1` |
| `tests/unit/test_retrieval_backends.py`, `test_capec_selection.py`, `test_generation_t5.py` | present; collected by fresh pytest |
| GitHub Actions run #6 | historical evidence: success on Python 3.11/3.12 |

## Documents and artifacts (claims not independently re-measured)

| Artifact | Claim | Status |
|---|---|---|
| `docs/paper-reproduction.md` | 114.560 CVE, 87/100, 55.420 rows | NOT VERIFIED locally |
| `docs/analysis.md` | independent metrics + circularity | code/benchmark partially verified; metrics doc-only |
| `docs/t5-stage1-eval-vi.md`, `docs/t5-stage1-paper10-eval-vi.md` | leakage, collapse, BLEU | NOT VERIFIED in this audit (source docs only) |
| `docs/hybrid-two-stage-vi.md` | 0,7508 hybrid | NOT COMPARABLE; doc-only |
| `docs/generation-quality.md` | repetition/BLEU improvement on 28 cases | NOT VERIFIED; decoding tuning disclosed |
| `docs/human-evaluation/*` | candidate 20 CVE, protocol | BLOCKED |
| `reports/public-schema-compatibility-audit.md` | strict schema risk | VERIFIED via probe script in that audit |
| `reports/evidence-and-lab-implementation-report.md` | schema + Docker assertions | historical batch, not rerun here |

## Explicitly not accessed

- Kaggle account, kernels, checkpoints or logs (per constraint).
- Docker daemon / compose / containers (per constraint; risk to ports and volumes).
- Any external consumer of the public schema (NOT EVALUATED).
- GitHub Actions API (run #6 is historical context, not re-fetched in this audit).
