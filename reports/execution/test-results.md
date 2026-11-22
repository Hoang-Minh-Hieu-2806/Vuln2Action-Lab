# Test results — Batch 0/1 (fresh, 2026-11-22)

| Command | Exit | Result | Notes |
|---|---:|---|---|
| `git status --short --branch` | 0 | 7 modified + 5 untracked paths | pre-existing, preserved |
| `git log -1 --oneline` | 0 | `4283360 ...` | baseline |
| `git diff --stat` / `git diff` | 0 | 7 files, 141 insertions, 1 deletion | provenance batch, not this batch |
| `python -m ruff check src api scripts tests evaluation gui` | 0 | All checks passed | CI scope |
| `python -m pytest -q` | 0 | 248 passed, 6 skipped | 6 = Docker opt-in skipped |
| `python -m vuln2action.cli --list-samples` | 0 | 3 samples printed | CVE-2024-0001/0002/0003 |
| `python -c "subprocess... --json-only"` | 0 | STATUS SIMULATED, PROVIDER rule_based, STEPS 5 | evidence keys: checkpoint_id, collected_at, command_outputs, generation, http, logs, plan, validation_result, workflow |

Not executed this batch: `V2A_DOCKER_TESTS=1` Docker integration (port/container
interference risk); `ruff check .` (known 5 pre-existing labs errors, unchanged);
Kaggle CLI; CI triggers.

Historical evidence (not re-run): Docker opt-in 6 passed in 50,58s; GitHub CI run #6
success. These are labelled historical, not fresh results.
