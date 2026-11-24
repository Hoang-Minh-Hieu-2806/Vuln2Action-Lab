# Rehearsal 01 — Final Defense Gate

- Date/Time (UTC): 2026-11-24T15:46:26Z → 2026-11-24T15:48:07Z
- Operator: OpenCode agent (browser automation via `playwright-cli`)
- Environment: Windows, Python 3.13, Flask local GUI on `127.0.0.1:5000`, browser Chromium
- Commit/HEAD: `0394b3dd7e5886410eb2004d9806fcd1e6153e09` on `dev`
- Frozen demo run ID: `final-cve001-20261123T065251Z`
- New rehearsal run ID: `agent-rehearsal-20261124T141644Z`
- Demo script: `docs/defense/demo-script-vi.md`
- Outcome: **PASS for agent-executable steps**; Docker and human slide presentation remain out of scope.

## Steps executed

| Step | Script step | Command / action | Actual result | Exit |
|---|---|---|---|---|
| 1 | Step 1 | Read demo script and frozen artifact inventory | Artifact root verified: 17 files, 2 screenshots | n/a |
| 2 | Step 2 | `vuln2action --list-samples` | 3 SAMPLE CVEs listed; `CVE-2024-0001 (cve-001)` present | 0 |
| 3 | Step 2 | `vuln2action --sample CVE-2024-0001 --json-only` | 360-line JSON; `provider=rule_based`, `result.status=SIMULATED`, `checkpoint_id=null` | 0 |
| 4 | Step 3 | Read `evidence/provenance.json` + `evidence/report.json` | `retrieval.backend=semantic`, CWE-79/CWE-352/reference metadata present | n/a |
| 5 | Step 4 | Browser: open `http://127.0.0.1:5000`, fill `CVE-2024-0001`, click Analyze | Page showed `CAPEC-591`, `Generation status: unavailable (unavailable)`, and heading `Reference execution flow (CAPEC catalog, not generated)` | 0 |
| 6 | Step 5 | Read frozen validator artifact | `validator/validation.json` status `SIMULATED`; no new PASS created | n/a |
| 7 | Step 6 | `python scripts/verify_demo_freeze.py` | `DEMO FREEZE VERDICT: PASS`, 14 SHA-256 entries verified | 0 |
| 8 | Step 7 | Read `docs/defense/limitations-slide.md` | Numbers and SIMULATED/reference-flow wording present | n/a |

## Screenshot

- `artifacts/demo/agent-rehearsal-20261124T141644Z/screenshots/rehearsal-01.png`
- Size: 45,332 bytes
- SHA-256: `9e76f23dfb81f8a18d75dc8e208456ced00a304e03638045cdddf69590facc65`

## Errors

- Browser console had one non-blocking entry (favicon); no page failure.
- Initial server start attempt exited; second start succeeded with PID 28344.

## Manual intervention / out of scope

- Docker lab `--execute` not run (out of scope); verdict remains `SIMULATED`.
- Limitations slide presentation to a human reviewer remains a human action.

## Teardown

- Browser `default` closed via `playwright-cli close`.
- Flask server stopped; port 5000 listen count = 0.

## Verdict

**PASS for agent-executable steps.** Not a claim of Docker validation or human slide presentation.
