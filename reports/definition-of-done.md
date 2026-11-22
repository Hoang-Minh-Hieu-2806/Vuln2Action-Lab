# Definition of Done — Vuln2Action-Lab roadmap

Distinguish these states; never use DONE for a lower state.

| State | Meaning |
|---|---|
| Implemented | Code exists and is reviewed |
| Tested | Unit/integration test exists and passes locally |
| Experimentally evaluated | Metrics produced from a real run with recorded config/artifact |
| Reproducible | Third party can regenerate artifacts from repo + documented inputs |
| Demonstrable | A live demo path exists with saved log/screenshot |
| Ready for release | External consumers and compatibility verified |

## Per workstream acceptance criteria

### Core engineering
- **CI on `dev`**: trigger present in `.github/workflows/ci.yml`; a GitHub run on push to `dev` is success. Evidence: run URL. Status: tested (run #6 historical).
- **Docker CI job**: separate job, `needs: quality`, `V2A_DOCKER_TESTS=1`, 6 integration tests pass on GitHub runner, teardown `if: always()`, no orphan containers. Evidence: run URL. Status: not implemented.
- **Executor safety**: non-local target rejected before subprocess; generated text never in argv; manifest-only commands; no `shell=True`. Evidence: `test_executor.py` + integration assertion tests. Status: tested.
- **Schema change**: old artifact loads, new artifact round-trips, strict external impact documented. Evidence: `tests/unit/test_evidence_provenance.py`, `reports/public-schema-compatibility-audit.md`. Status: tested; external NOT EVALUATED.

### Research and evaluation
- **Dataset claims**: counts must be recomputed from an artifact with SHA-256; doc-only is NOT VERIFIED. Evidence: dataset file + hash. Status: not done.
- **Independent CAPEC benchmark**: frozen file + hash + protocol + limits. Evidence: `docs/evaluation/capec-independent-freeze.md`. Status: done (freeze), metrics doc-only.
- **Leakage statement**: report states 11,083/11,089 overlap and that BLEU is not generalization. Evidence: `docs/t5-stage1-eval-vi.md`. Status: documented.
- **Stage-1 result**: `metrics.json`, `predictions.jsonl`, `training_config.json`, checkpoint, real epoch/precision/GPU recorded. Evidence: files. Status: blocked.
- **Human evaluation**: `splits.json` case list, 20 outputs, protocol, rubric, form, advisor-filled scores, 1-reviewer declaration. Evidence: files + form. Status: blocked.
- **Group-split**: group ids disjoint across train/val/test, overlap report, fixed test. Evidence: manifest + hash. Status: plan only.

### Integration and presentation
- **GUI**: `reference_flow` and `generated_flow` separate fields; no checkpoint → generated null with status; labels visible; tests pass. Evidence: `test_gui.py` + screenshot. Status: partially done (plumbing not implemented).
- **Demo pack**: command from CVE input to evidence output runs from clean clone; PASS/FAIL and evidence captured; screenshot and log saved. Evidence: `report.json`, log, screenshot. Status: partially done (code exists, pack not frozen).
- **Paper deviation report**: no `PENDING KAGGLE ARTIFACT` unless explicitly BLOCKED; all 14 deviation rows filled; no overclaim. Evidence: `docs/paper-deviation-report-vi.md`. Status: draft.
- **Defense readiness**: can explain retrieval, generation, lab, evidence, limitations, and can reproduce the demo live. Evidence: checklist signed by team. Status: not done.

## Global release gate

All of: tested + experimentally evaluated + reproducible + demonstrable + external compatibility verified.
A project can be **minimum defensible** without the global release gate, but must
state exactly which gates are missing.
