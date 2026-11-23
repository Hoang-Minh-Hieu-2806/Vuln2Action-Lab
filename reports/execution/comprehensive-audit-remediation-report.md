# Comprehensive audit remediation report — Vuln2Action-Lab

Date: 2026-11-23. Branch `dev`, baseline HEAD `a152519`. No commit/push.

## A. Executive summary

- Findings audited: 13 (10 main + 3 smaller).
- Fixed and tested: 12.
- Already fixed and verified: 0.
- Disputed: 0.
- Blocked: 1 (API runtime test — FastAPI not installed; code change made, test skipped with explicit reason).
- Deferred: 0.
- Kaggle, Docker integration, benchmark data, historical evidence: untouched.

## B. Finding-by-finding matrix

| # | Finding | Verification | Change | Tests | Result | Status |
|---|---|---|---|---|---|---|
| 1 | `--stage reproduction` exits 0 | `main(["--stage","reproduction"])` → 0 | Remove choice; `parser.error` on unsupported | `test_run_evaluation.py` (6) | 6 passed; shell exit 2 | FIXED_AND_TESTED |
| 2 | `make clean` deletes results | Makefile recipe text | Remove `results/*`; document scope | `test_evidence_preservation.py::test_make_clean...` | 1 passed | FIXED_AND_TESTED |
| 3 | Raw XML silently changes retrieval | `default_semantic_enricher()` read untracked files | Tracked seed only | `test_retrieval_determinism.py` (2) | 17 targeted passed | FIXED_AND_TESTED |
| 4 | Truncated/overwritten reports | `write_json` plain `"w"` | Atomic mkstemp+fsync+replace; collide guard | `test_evidence_preservation.py` (6) | 22 targeted passed | FIXED_AND_TESTED |
| 5 | GUI crash on fresh clone | `create_app()` → FileNotFoundError | Actionable RuntimeError, no fake data | `test_gui_fresh_clone.py` | 3 GUI tests passed | FIXED_AND_TESTED |
| 6 | `enabled` flags ignored | Config + `get_generator` | Remove flags; CLI name is sole switch | `test_provider_config.py` (7) | 35 targeted passed | FIXED_AND_TESTED |
| 7 | Provenance retrieval always NOT_AVAILABLE | Sidecar code | Record runtime backend/score; CAPEC score excluded | `test_provenance_retrieval.py` (4) | 17 targeted passed | FIXED_AND_TESTED |
| 8 | Three `_mean_vector` copies | Source compare | `utils/vectors.py` canonical helper | `test_vector_math.py` (5) | 23 targeted passed | FIXED_AND_TESTED |
| 9 | Dead harnesses | Whole-tree grep; two stubs only raise | Delete two stubs; keep+document `evaluate_tfidf.py` | full suite | 304 passed, 7 skipped | FIXED_AND_TESTED |
| 10 | `read_jsonl` materialises all rows | 7 callers checked | Generator; `list()` at random-access sites | `test_jsonl_streaming.py` (7) | 14 targeted passed | FIXED_AND_TESTED |
| 11 | CLI help misleading | `--help` text | Label LLM as stub | `test_quality_fixes.py` | 2 passed | FIXED_AND_TESTED |
| 12 | report.md injection | f-string with raw values | `_md_inline` escaping | `test_quality_fixes.py` | same 2 passed | FIXED_AND_TESTED |
| 13 | Config loaded per API request | Every route called `load_settings()` | Load once in `create_app()`, store on `app.state` | `test_api_loads_settings_once...` | SKIPPED (FastAPI missing) | BLOCKED (test only) |

## C. Architecture impact

- Evidence writes are atomic per file; sidecar first, then `report.json`; the pair is **not** one transaction.
- `save_report` refuses an existing `report.json` unless `overwrite=True`.
- Retrieval defaults to tracked seed corpus; raw XML no longer discovered implicitly.
- Provider choice comes only from `--provider`/settings default; config `enabled` removed.
- GUI fails with an actionable message when the untracked dataset is absent; no synthetic fallback.
- Word2Vec mean-vector math lives in `vuln2action/utils/vectors.py`, used by CAPEC ranking and ExploitDB mapping.
- `read_jsonl` is a generator; callers needing slicing/`len()`/reuse call `list()` explicitly.
- API config loaded once into `app.state.settings`; tests can override that attribute.

## D. Compatibility

- `EvidenceBundle` and `Workflow` schemas unchanged; no new public fields.
- Provenance remains a sidecar; `generation.provenance_ref` remains optional.
- Legacy sidecars with `NOT_AVAILABLE` retrieval still validate (tests pass).
- Legacy reports without provenance reference still readable (existing tests pass).
- New strict config rejects `enabled`; this is a deliberate single-source-of-truth change.
- External consumers still NOT EVALUATED.

## E. Research integrity

No benchmark result, checkpoint, dataset, or container digest was invented. No historical BLEU/ROUGE, frozen label, or threshold was changed. No T5 fine-tuned run was claimed. SHA-256 is described only as byte integrity, not source trust.

## F. Validation

| Command | Result |
|---|---|
| `python -m pytest -q -rs` | 304 passed, 7 skipped, exit 0 |
| Skips | 6 Docker opt-in (`V2A_DOCKER_TESTS=1`); 1 FastAPI missing |
| `python -m ruff check src api scripts tests evaluation gui` | All checks passed, exit 0 |
| `python -m ruff check .` | exit 1 — 5 pre-existing labs errors (RUF100×2, PLW1510×3), out of approved scope |
| CLI smoke `--sample CVE-2024-0001 --json-only` | `SIMULATED`, 9 evidence keys |
| Retrieval evaluation `--stage retrieval --json-only` | keyword/semantic/tfidf |
| `python scripts/run_evaluation.py --stage reproduction` | exit 2, explicit invalid choice |

## G. Remaining risks

- API settings lifecycle code is not executed here because FastAPI is absent; install `[api]` and rerun `test_quality_fixes.py`.
- Docker lab integration remains opt-in and was not run (explicit constraint).
- Full Ruff still red on lab helper subprocess calls already handled by lab logic; fix in a separate batch.
- Old configs containing `enabled` now fail validation; document as migration note if deployed externally.
- Kaggle stage-1 artifact still unavailable; report remains honest about that.

## H. Git state

Branch `dev`, HEAD `a152519`, no commit/push. Modified tracked: Makefile, API files, config/models.yaml, two deleted harness files, gui/app.py, report trace, audit/hybrid/eval CLI scripts, core source files, test_cli.py. Untracked: new tests and `utils/vectors.py`, `post-kaggle-roadmap.md`. Pre-existing user changes (cli.py stdout fix, test_cli.py, graph audit corrections) were preserved. A stray folder caused by a mistyped Windows path outside the repo was removed; no project data was touched.
