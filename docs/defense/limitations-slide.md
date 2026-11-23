# Limitations & readiness slide

Use this slide to state what is verified and what is not. Do not merge the four
readiness dimensions into one status.

## 1. Engineering — READY

- CI run #10/#11 success on Python 3.11 and 3.12; Ruff pinned to 0.17.3.
- Local: 327 passed, 7 skipped (6 Docker opt-in, 1 FastAPI absent globally).
- API verified inside isolated venv on `127.0.0.1` only; 4 routes returned 200.
- Evidence writes are atomic; provenance digest and path guards verified.

## 2. Demo — READY WITH KNOWN LIMITATIONS

- Demo runs: `final-cve001-20261123T065251Z`,
  `rehearsal-cve001-20261123T080038Z`. Both `SIMULATED`, consistency all true.
- CLI, evidence, provenance, report JSON/Markdown, screenshots and SHA-256 present.
- GUI fixture is local-only: 3 sample CVEs + 615 CAPEC records, no predictions,
  no technique map, empty reference file. `/`, `/health`, `/api/analyze` return 200.
- Docker lab validation not run; no real `PASS`/`FAIL` claim.

## 3. Research — NOT READY

- Kaggle kernel last observed `RUNNING`, GPU 30.30/30h, remaining 0, logs empty.
- No `metrics.json`, `predictions.jsonl` or final checkpoint artifact locally.
- BLEU/ROUGE = **PENDING**, not computed or inferred.
- Human evaluation blocked: no authoritative `splits.json`, no advisor contact.
- Group split is a plan only; no retrain, no dataset change.

## 4. Defense — READY WITH LIMITATIONS

Defend the engineering and caveated negative-result story only. Do **not** claim:

- full paper reproduction or 50 completed epochs;
- T5 fine-tuned effectiveness from the local demo;
- three-expert human evaluation or Table 6 reproduction;
- generalization on the leaked validation split (11,083/11,089 targets overlap train);
- real Docker PASS/FAIL from simulated runs.

## Evidence pointers

- `reports/execution/finalization-campaign-report.md`
- `reports/execution/pony-tail-optimization-report.md`
- `docs/paper-deviation-report-vi.md`
- `artifacts/demo/final-cve001-20261123T065251Z/`
- `artifacts/demo/rehearsal-cve001-20261123T080038Z/`
- `data/processed/reproduction/DEMO_FIXTURE.md`

## Q&A line

"Local CLI/API/evidence path is reproducible and CI is green; research claims beyond
the documented negative-result caveats remain pending artifact verification."
