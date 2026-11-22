# Evidence index — Batch 0/1

| Evidence | Source | Result | Used for |
|---|---|---|---|
| Git state | `git status --short --branch`, `git log -1 --oneline`, `git diff --stat`, `git diff` | 7 modified, 5 untracked, HEAD 4283360 | baseline integrity |
| CLI list | `python -m vuln2action.cli --list-samples` | 3 sample CVEs | input source |
| CLI JSON | `--sample CVE-2024-0001 --json-only` | SIMULATED, rule_based, 5 steps | workflow + evidence shape |
| Source trace | `cli.py:16-74`, `pipeline/run.py:36-95`, `pipeline/analyze.py:56-73`, `generation/rule_based.py:11-49`, `reproduction/planner.py:7-22`, `executor.py:21-163`, `validator.py:7-63`, `evidence/collector.py:16-46`, `evidence/reporter.py:24-45` | full path identified | T5 data flow |
| Security grep | `Select-String 'shell\s*=\s*True'` | zero matches | no arbitrary shell |
| Tests | `python -m pytest -q` | 248 passed, 6 skipped | regression baseline |
| Lint | `python -m ruff check src api scripts tests evaluation gui` | exit 0 | code quality |
| Mermaid flow | `reports/execution/t5-end-to-end-audit.md` section 2 | diagram | documentation |

No screenshot was captured (`SCREENSHOT_NOT_CAPTURED`). No Docker log was produced
in this batch. No Kaggle artifact was downloaded or inspected.
