# Full audit risk register — 2026-11-22

Severity: HIGH / MEDIUM / LOW. Likelihood: HIGH / MEDIUM / LOW.
Impact: research validity, demo credibility, reproducibility or safety.

| ID | Risk | Severity | Likelihood | Impact | Evidence | Mitigation (not applied) |
|---|---|---|---|---|---|---|
| R1 | Stage-1 T5 result missing; core paper claim unproven | HIGH | HIGH | Cannot claim reproduction | no Kaggle artifact in repo; `docs/paper-reproduction.md` | obtain metrics/checkpoint, log 5 epochs/FP32/T4 x2 |
| R2 | Validation leakage 11,083/11,089 | HIGH | HIGH | BLEU not generalisation | `docs/t5-stage1-eval-vi.md:51` | group-split holdout (`docs/evaluation/t5-group-split-plan.md`) before quoting BLEU |
| R3 | 120-CVE benchmark circular | HIGH | HIGH | Top-1 87/100 meaningless as ranking evidence | `docs/analysis.md:16-30` | use independent 21-case set as primary; report 12/21 coverage |
| R4 | Model collapse (25 unique predictions / 11.089) | HIGH | HIGH | Generated workflow low utility | `docs/t5-stage1-paper10-eval-vi.md:47-51` | stop blind epoch increases; fix target diversity or use CAPEC-conditioned as separate track |
| R5 | GUI shows reference flow, not generated | HIGH | HIGH | Demo mislabeled / cannot show T5 contribution | `gui/app.py:147` | add `reference_flow`/`generated_flow` with labels; no checkpoint → null |
| R6 | Lab uses fixed marker; workflow not driving payload | HIGH | MEDIUM | "T5 reproduces vulnerability" claim unsupported | `labs/cve-001/validation/labctl.py:31-32`, `executor.py:21-31` | validator accepts allowlisted marker from workflow; retest counterfactuals |
| R7 | CI green without Docker lab verification | MEDIUM | HIGH | False confidence in PASS/FAIL | `.github/workflows/ci.yml`; 2 Docker tests skipped | enable separate Docker job after GitHub-hosted green run |
| R8 | Dataset not reproducible from clean clone | HIGH | HIGH | Third party cannot verify 114.560 numbers | `data/processed/reproduction` absent; tracked only .gitkeep | publish versioned dataset with hash or exact rebuild commands/snapshots |
| R9 | checkpoint_id is a string, not weight hash | MEDIUM | MEDIUM | Provenance can be questioned | `domain/workflow.py`, `domain/evidence.py`, `reports/public-schema-compatibility-audit.md` | record artifact digest or model card id |
| R10 | Strict external schema rejects new JSON | MEDIUM | MEDIUM | Downstream integration break | `extra="forbid"`, `OLD_STRICT_READS_NEW: NO` | minor version + migration note; confirm with downstream |
| R11 | `ruff check .` red (5 labs errors) | LOW | HIGH | Local quality gate inconsistent with CI | `app.py:35,47 RUF100`; `labctl.py:37,47,55 PLW1510` | separate cleanup batch; then make full-scope ruff the gate |
| R12 | Human evaluation blocked on external split | MEDIUM | HIGH | Schedule risk before defense | `docs/human-evaluation/README.md` | obtain `splits.json` early, generate 20 workflows, engage advisor |
| R13 | Different BLEU protocols conflated | HIGH | MEDIUM | Misleading comparison in defense | `docs/t5-stage1-paper10-eval-vi.md:213-221`, `docs/hybrid-two-stage-vi.md:189-191` | always label CVE-only / gold-CAPEC / hybrid separately |
| R14 | Docker port/container collisions | MEDIUM | MEDIUM | Flaky tests | fixed ports 18001/18011, fixed container names | serial job, `if: always()` teardown, unique project names |
| R15 | Local raw XML changes retrieval metric | LOW | HIGH | Reported P@3 differs by environment | `retrieval/semantic.py:236-240` | document clean-checkout vs enriched value; pin snapshot |
| R16 | CAPEC coverage ceiling 12/21 | MEDIUM | HIGH | Independent score capped regardless of ranker | `docs/analysis.md:159` | report coverage as structural limitation |

Top 5 for defense: R1, R2, R3, R5, R13.
