# Limitations & readiness slide

Use this slide to state what is verified and what is not. Do not merge the four
readiness dimensions into one status.

## 1. Engineering — READY

- CI run #10/#11 success on Python 3.11 and 3.12; Ruff pinned to 0.17.3.
- Local: 327 passed, 7 skipped (6 Docker opt-in, 1 FastAPI absent globally).
- API verified inside isolated venv on `127.0.0.1` only; 4 routes returned 200.
- Evidence writes are atomic; provenance digest and path guards verified.

## 2. Demo — READY WITH KNOWN LIMITATIONS

- Frozen demo: `final-cve001-20261123T065251Z`; 14/14 SHA-256 entries verified,
  `consistency.all_pass=true`, verdict `SIMULATED`, provider `rule_based`.
- Verify read-only with `python scripts/verify_demo_freeze.py`.
- CLI, evidence, provenance, report JSON/Markdown and two screenshots are present.
- GUI fixture is local-only: 3 sample CVEs; `/`, `/health`, `/api/analyze` return 200.
- GUI now labels `reference_flow` explicitly and reports `generation_status=unavailable`;
  it never labels CAPEC reference flow as T5-generated.
- Docker lab validation not run; no real `PASS`/`FAIL` claim.

## 3. Research — PARTIAL (observed validation only)

- Kaggle kernel `alexdannguyen/v2a-stage1-resume-checkpoint-3465` is `COMPLETE`;
  resume `3465 → 4158`, epoch 6, FP32 on 2×T4.
- Artifacts in `data/external/resume_cp3465/`: config, trainer state, metrics,
  11,089 predictions and kernel log; SHA-256 inventory in `docs/t5-stage1-final-vi.md`.
- Observed validation: BLEU 0.4802, ROUGE-L F1 0.5659 on 11,089 rows.
- Leakage 11,083/11,089: not generalization, not independent evaluation,
  not paper-comparable, not successful paper reproduction.
- Full checkpoint weights are not local; only metadata and log were downloaded.
- Human evaluation blocked: no authoritative `splits.json`, no advisor contact.
- Group split is a plan only; no retrain, no dataset change.

## 4. Defense — READY WITH LIMITATIONS

Defend the engineering and caveated negative-result story only. Do **not** claim:

- full paper reproduction or 50 completed epochs;
- T5 fine-tuned effectiveness from the local demo;
- three-expert human evaluation or Table 6 reproduction;
- generalization on the leaked validation split (11,083/11,089 targets overlap train);
- real Docker PASS/FAIL from simulated runs.

## 5. Future work

- Independent group-based evaluation: T8 group-split plan exists, but no manifest
  or holdout artifact is implemented.
- Human evaluation: T3 blocked; needs authoritative `splits.json`, 20 workflow
  outputs and 1 advisor reviewer.
- Docker CI verification: T6 not enabled; no GitHub-run PASS and no Docker
  integration test in this gate.

## Evidence pointers

- `docs/defense/defense-claims-vi.md`
- `docs/defense/demo-script-vi.md`
- `docs/t5-stage1-final-vi.md`
- `data/external/resume_cp3465/`
- `docs/paper-deviation-report-vi.md`
- `artifacts/demo/final-cve001-20261123T065251Z/`
- `scripts/verify_demo_freeze.py`
- `reports/execution/finalization-campaign-report.md`
- `reports/execution/pony-tail-optimization-report.md`
- `data/processed/reproduction/DEMO_FIXTURE.md`

## Q&A line

"Local CLI/API/evidence path is reproducible and CI is green; Stage 1 observed
validation has real artifacts, but leakage blocks generalization and reproduction
claims."
