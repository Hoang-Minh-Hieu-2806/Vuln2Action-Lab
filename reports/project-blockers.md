# Project blockers and external dependencies

## Active blockers

| ID | Blocker | Type | Affected tasks | Current evidence | Handling |
|---|---|---|---|---|---|
| B1 | Kaggle stage-1 kernel completion + artifact | External compute | T1, T2 numbers, T3 outputs, T4 wiring, T7 | notebook dirs + docs only; no `metrics.json` locally | wait; do NOT restart/cancel/modify kernel; fallback Level 1 + BLOCKED note |
| B2 | `data/processed/reproduction/splits.json` and full dataset | External data owner | T3, T8, dataset verification | `data/processed/reproduction` absent | request from dataset owner or rebuild with documented commands; no fabricated case list |
| B3 | Advisor availability for 20-CVE review | External person | T3 | `docs/human-evaluation/` candidate package only | send form early; if unavailable, mark NOT EVALUATED |
| B4 | GitHub-hosted Docker runner verification | External CI | T6 | plan + local Docker 6 passed historical | enable only after one green GitHub run |
| B5 | Checkpoint identity for GUI generated flow | Derived from B1 | T4 | `config/models.yaml:checkpoint: ""` | no untuned t5-small relabeling; generated null until checkpoint present |
| B6 | External strict-schema consumers unknown | External ecosystem | T9 / release | `reports/public-schema-compatibility-audit.md`: NOT EVALUATED | delay public release; internal demo unaffected |

## Dependencies by task

- T1 depends only on B1.
- T2 depends on independent freeze (done) plus T1 for final numbers; can publish "allowed claims" table before T1.
- T3 depends on B2, B3 and T1-generated outputs.
- T4a (GUI plumbing) has no external dependency; T4 (generated view) depends on B1/B5.
- T5 depends on local Docker only; no external blocker.
- T6 depends on B4; assertions already implemented locally.
- T7 depends on T1 + T2.
- T8 depends on B2 dataset snapshot.
- T9 depends on T1 artifact and a schema audit re-check.

## Contingency decisions

| If blocked | Do | Do not |
|---|---|---|
| B1 not resolved before defense | Freeze Level 1, state BLOCKED, show toy local T5 artifact with clear label | invent BLEU, claim reproduction |
| B2 not shared | Human eval NOT EVALUATED; use candidate CVE list only as provenance | fabricate 20 cases or scores |
| B3 unavailable | Report advisor review pending | write "3 experts" |
| B4 red on Ubuntu | Keep job opt-in / disable job | set `continue-on-error` |
| B5 no checkpoint | GUI shows reference with label | fake generated flow |

## Escalation orders (who to ask)

- B1: Kaggle account owner `phamquang0606` — ask only for artifact export after run finishes.
- B2: dataset owner of `dangthiet/vuln2action-p0-stage1` / `splits.json`.
- B3: faculty advisor.
- B4/B6: repository owner / downstream consumer owners.
