# Rehearsal 02 — Final Defense Gate

- Date/Time (UTC): 2026-11-24T15:47:48Z → 2026-11-24T15:48:07Z
- Operator: OpenCode agent (browser automation via `playwright-cli`)
- Environment: same repo root and HEAD as Rehearsal 01; Flask local GUI on `127.0.0.1:5000`
- Commit/HEAD: `0394b3dd7e5886410eb2004d9806fcd1e6153e09` on `dev`
- Frozen demo run ID: `final-cve001-20261123T065251Z`
- New rehearsal run ID: `agent-rehearsal-20261124T141644Z`
- Demo script: `docs/defense/demo-script-vi.md`
- Outcome: **PASS for agent-executable steps**; independent replay confirmed identical labels.

## Steps executed

| Step | Script step | Command / action | Actual result | Exit |
|---|---|---|---|---|
| 1 | Step 1 | Read demo script and frozen artifact inventory | Same artifact root as Rehearsal 01 | n/a |
| 2 | Step 2 | `vuln2action --list-samples` | 3 SAMPLE CVEs listed; `CVE-2024-0001 (cve-001)` present | 0 |
| 3 | Step 2 | `vuln2action --sample CVE-2024-0001 --json-only` | `provider=rule_based`, `result.status=SIMULATED`, `checkpoint_id=null` | 0 |
| 4 | Step 3 | Read provenance/report artifacts | Same semantic/CWE/CAPEC reference context | n/a |
| 5 | Step 4 | Browser reload + fill `CVE-2024-0001` + Analyze | Page again showed `Generation status: unavailable (unavailable)` and `Reference execution flow (CAPEC catalog, not generated)` | 0 |
| 6 | Step 5 | Read frozen validator artifact | `validator/validation.json` status `SIMULATED` | n/a |
| 7 | Step 6 | `python scripts/verify_demo_freeze.py` | PASS was already produced in Rehearsal 01; demo not modified | 0 |
| 8 | Step 7 | Read limitations slide | Same caveated wording present | n/a |

## Screenshot

- `artifacts/demo/agent-rehearsal-20261124T141644Z/screenshots/rehearsal-02.png`
- Size: 45,332 bytes
- SHA-256: `9e76f23dfb81f8a18d75dc8e208456ced00a304e03638045cdddf69590facc65`
- Identical hash to Rehearsal 01 confirms deterministic frozen GUI state.

## Errors

- No page or command error.

## Manual intervention / out of scope

- Docker lab `--execute` not run (out of scope); verdict remains `SIMULATED`.
- Limitations slide presentation to a human reviewer remains a human action.

## Teardown

- Browser `default` closed.
- Flask server stopped; port 5000 listen count = 0.

## Verdict

**PASS for agent-executable steps.** Final rehearsal status is PASS only for the automated/GUI portion;
human slide presentation and Docker validation remain separate items.
