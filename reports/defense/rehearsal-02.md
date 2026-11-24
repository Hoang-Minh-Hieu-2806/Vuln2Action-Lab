# Rehearsal 02 — Final Defense Gate

- Date/Time (UTC): not started
- Operator: pending human operator
- Environment: same repo root and HEAD as Rehearsal 01
- Commit/HEAD expected: `0394b3dd7e5886410eb2004d9806fcd1e6153e09` on `dev`
- Demo run ID: `final-cve001-20261123T065251Z`
- Demo script: `docs/defense/demo-script-vi.md`
- Outcome: **AWAITING HUMAN REHEARSAL** (not PASS, not FAIL)

## Status

Rehearsal 2 was not started because Rehearsal 1 ended as `PARTIAL — AWAITING HUMAN ACTION`.
Per acceptance criteria, a second independent replay only counts after the first rehearsal
completes all steps. No output was fabricated and no frozen artifact was modified.

## Required human steps for Rehearsal 2

1. From repo root, run:
   - `vuln2action --list-samples`
   - `vuln2action --sample CVE-2024-0001 --json-only`
2. Start the local GUI with `python gui/app.py` and open `http://127.0.0.1:5000`.
3. Enter sample `CVE-2024-0001`.
4. Visually confirm the page labels the flow as reference/CAPEC metadata and shows
   generation status `unavailable`; it must not say T5-generated.
5. Show `artifacts/demo/final-cve001-20261123T065251Z/validator/validation.json` with
   `status=SIMULATED`; do not claim Docker PASS.
6. Run `python scripts/verify_demo_freeze.py` and confirm `DEMO FREEZE VERDICT: PASS`.
7. Show the limitations slide before Q&A.

## Errors

- None recorded, because no execution was attempted.

## Manual intervention required

- Entire rehearsal requires human interaction for the visual GUI step and for any
  decision to run Docker lab validation. Docker remains out of scope for this gate.

## Total duration

- Not measured.

## Verdict

**AWAITING HUMAN REHEARSAL.** Final rehearsal status cannot be PASS until both
Rehearsal 1 and Rehearsal 2 are actually completed by a human operator.
