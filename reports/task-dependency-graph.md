# Task dependency graph — next action roadmap

Nodes: external blockers (square-ish via quotes), tasks (T1-T9), milestones (M1-Final).

```mermaid
flowchart TD
  EXT1["Kaggle kernel RUNNING - external"]
  EXT2["splits.json + 20 workflow outputs"]
  EXT3["Advisor availability"]
  EXT4["GitHub-hosted runner"]

  T1["T1 P0 - capture stage-1 artifact"]
  T2["T2 P0 - publishable claims + leakage"]
  T3["T3 P1 - human evaluation"]
  T4A["T4a P1 - GUI plumbing"]
  T4["T4 P1 - generated flow view"]
  T5["T5 P1 - rule-based demo + evidence"]
  T6["T6 P2 - Docker CI job"]
  T7["T7 P1 - deviation report final"]
  T8["T8 P2 - group-split holdout"]
  T9["T9 P3 - weight digest"]

  M1["M1 - demo + claims locked"]
  M2["M2 - artifact + report + GUI plumbing"]
  M3["M3 - human eval + holdout + GUI wiring"]
  FINAL["Final - CI + replay + freeze"]

  EXT1 --> T1
  T1 --> T2
  T1 --> EXT2
  EXT2 --> T3
  EXT3 --> T3
  T1 --> T7
  T2 --> T7
  T4A --> T4
  T1 --> T4
  T5 --> M1
  T2 --> M1
  T1 --> M2
  T7 --> M2
  T4A --> M2
  T3 --> M3
  T8 --> M3
  T4 --> M3
  T8 --> T2
  EXT4 --> T6
  T6 --> FINAL
  M1 --> FINAL
  M2 --> FINAL
  M3 -. optional .-> FINAL
  T9 -. optional .-> FINAL
```

## Critical path (longest dependency chain)

`EXT1 -> T1 -> T2 -> T7 -> M2 -> Final`.

Fallback when EXT1 never resolves:
`T5 -> T2 -> T7 -> Final (Level 1 only)`; T1/T4/T9 are marked BLOCKED, not delayed indefinitely.

## Parallelisable with the critical path

- T5 demo pack (no Kaggle dependency).
- T4a GUI plumbing (no checkpoint needed).
- T6 CI job (needs only GitHub runner + existing assertions).
- T8 group-split protocol design (needs dataset snapshot, not checkpoint).
- T3 document preparation (needs advisor confirmation; scores must wait).

## Conflicts to avoid

- T4 and T7 must not both edit the same report; T4 touches GUI/tests, T7 touches docs report.
- T2 and T7 share `docs/paper-deviation-report-vi.md`: T2 writes the claims table,
  T7 fills artifact-dependent values; sequence T2 before T7.
- T8 must not modify `evaluation/datasets/capec_independent.json` (frozen).
