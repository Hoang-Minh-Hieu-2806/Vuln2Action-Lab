# Blocker register — Batch 0/1

| Blocker | Status | Affected tasks | Input needed | Decision owner | Handling |
|---|---|---|---|---|---|
| Kaggle stage-1 artifact | BLOCKED | T1, T7, T4 generated view, T3 outputs | metrics.json, checkpoint, training log from completed run | user / Kaggle account owner | no access this batch; do not wait indefinitely |
| splits.json + 20 workflows | BLOCKED | T3 | official split from dataset owner + generated outputs | dataset owner | no synthetic cases |
| Advisor availability | BLOCKED | T3 | schedule + form | advisor | no emails sent this batch |
| Docker demo run authorization | PENDING USER DECISION | T5 Batch 3 | permission to build cve-001 images and bind 127.0.0.1:18001/18011 | user | do not start Docker without confirmation |
| Screenshot capture | NOT DONE | T5 Batch 3 | working screenshot tool | user / operator | else write SCREENSHOT_NOT_CAPTURED |
| GitHub-hosted Docker run | NOT EVALUATED | T6 | CI runner availability | repo owner | job remains off |

No blocker was resolved in Batch 0/1. No work was started on blocked tasks.
