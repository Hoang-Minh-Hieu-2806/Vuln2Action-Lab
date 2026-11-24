# Rehearsal 01 — Final Defense Gate

- Date/Time (UTC): 2026-11-24T07:59:30Z → 2026-11-24T07:59:40Z (agent CLI portion only)
- Operator: OpenCode agent
- Environment: Windows, Python 3.13, repo root `Vuln2Action-Lab`, no Docker started, no Kaggle call
- Commit/HEAD: `0394b3dd7e5886410eb2004d9806fcd1e6153e09` on `dev`
- Demo run ID: `final-cve001-20261123T065251Z`
- Demo script: `docs/defense/demo-script-vi.md`
- Outcome: **PARTIAL — AWAITING HUMAN ACTION** (not PASS)

## Steps executed by agent

| Step | Script step | Command / action | Actual result | Exit |
|---|---|---|---|---|
| 1 | Step 1 | Read demo script and frozen artifact inventory | Artifact root verified: 17 files, 2 non-empty screenshots | n/a |
| 2 | Step 2 | `vuln2action --list-samples` | 3 SAMPLE CVEs listed; `CVE-2024-0001 (cve-001)` present | 0 |
| 3 | Step 2 | `vuln2action --sample CVE-2024-0001 --json-only` | 360-line JSON; `provider=rule_based`, `result.status=SIMULATED`, `checkpoint_id=null`, `lab_id=cve-001` | 0 |
| 4 | Step 3 | Read `evidence/provenance.json` + `evidence/report.json` | `retrieval.backend=semantic`, CWE-79/CWE-352/reference metadata present | n/a |
| 5 | Step 4 | Read `workflow/workflow.json`, `workflow/plan.json`, GUI source | 5 stages; GUI `reference_flow` / `generated_flow=null` / `generation_status=unavailable` | n/a |
| 6 | Step 5 | Read frozen validator artifact | `validator/validation.json` status `SIMULATED`; no new PASS created | n/a |
| 7 | Step 6 | `python scripts/verify_demo_freeze.py` | `DEMO FREEZE VERDICT: PASS`, 14 SHA-256 entries verified | 0 |
| 8 | Step 7 | Read limitations slide | Numbers and SIMULATED/reference-flow wording present | n/a |

## Errors

- No command error in the agent-executed portion.

## Manual intervention required

- Step 5 of the original checklist (`vuln2action --sample CVE-2024-0001 --execute`) is **not executed**: it requires Docker lab validation, which is out of scope for this gate.
- Step 4 visual GUI interaction (`python gui/app.py` → `http://127.0.0.1:5000`) is **not executed** by the agent because it requires a human to open a browser and visually confirm the reference-flow label.
- A human must confirm the limitations slide is shown before Q&A.

## Total duration

- Agent CLI portion: ~10 seconds of command execution, within the 07:59:30Z–07:59:40Z window.
- Full rehearsal duration: not measurable until human steps are completed.

## Verdict

**PARTIAL — AWAITING HUMAN ACTION.** This is not a full rehearsal PASS because not all 7 steps were executed end-to-end and visual GUI interaction was not performed.
