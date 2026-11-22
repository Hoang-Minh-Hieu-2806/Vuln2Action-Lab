# Task status matrix — Batch 0/1

| Task ID | Roadmap status | Actual status | Evidence | Gap | Next action |
|---|---|---|---|---|---|
| T1 Kaggle artifact | BLOCKED | BLOCKED | no artifact in repo; kernel not accessed | metrics/checkpoint missing | wait external; no action this batch |
| T2 Claims lock | P0 | PARTIALLY VERIFIED | audit reports + independent freeze | final stage-1 numbers missing | Batch 4 |
| T3 Human eval | BLOCKED | BLOCKED | `docs/human-evaluation/` candidate only | splits.json + outputs + advisor | request inputs (Batch 5) |
| T4a GUI plumbing | P1 | PARTIALLY VERIFIED | `reports/gui-generation-preparation.md` | no code changes yet | Batch 6 |
| T4 generated view | P1 | BLOCKED | depends on T1 | checkpoint | after T1 |
| T5 rule-based demo | P0 | VERIFIED (logic) / PARTIALLY VERIFIED (artifacts) | fresh CLI smoke + source trace + historical Docker tests | packaged demo dir + screenshot | Batch 2/3 |
| T6 Docker CI | P2 | NOT IMPLEMENTED | plan only | GitHub-hosted run | after user approval |
| T7 Deviation final | P1 | BLOCKED on T1 | draft report | PENDING KAGGLE ARTIFACT | after T1 |
| T8 Group-split | P2 | PLAN ONLY | `docs/evaluation/t5-group-split-plan.md` | manifest not created | optional |
| T9 Provenance digest | P3 | NOT IMPLEMENTED | checkpoint_id is string | digest | defer |

Status is per task, not a single project-wide label.
