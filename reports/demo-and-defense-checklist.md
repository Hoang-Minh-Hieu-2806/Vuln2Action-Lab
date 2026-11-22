# Demo and defense checklist — Vuln2Action-Lab

## Demo script (primary, no checkpoint required)

1. Mở CLI: `vuln2action --list-samples` — cho thấy 3 CVE mẫu có nhãn SAMPLE (fake).
2. Chạy pipeline mô phỏng: `vuln2action --sample CVE-2024-0001 --json-only`.
   - Chỉ ra `result.status = SIMULATED`, `provider = rule_based`.
   - Chỉ ra `evidence.generation`, `evidence.workflow`, `evidence.plan`, `evidence.checkpoint_id = null`.
3. Chạy lab thật: `vuln2action --sample CVE-2024-0001 --execute`.
   - validator in `V2A_VALIDATION_JSON:{"status":"PASS",...}`.
   - Kiểm tra cả vulnerable lẫn patched counterfactual trong payload.
   - Chỉ ra evidence có command log + validation_result.
4. Mở GUI: `python gui/app.py` → `http://127.0.0.1:5000`.
   - Nhập CVE mẫu, xem CAPEC chọn + flow.
   - **Nói rõ**: đây là `reference_flow` từ MITRE, không phải T5-generated.
5. Kết thúc bằng slide limitations:
   - không reproduce paper; BLEU thấp; leakage; 1 reviewer; GUI chưa generated flow.

## Artifacts to capture

| Artifact | From | Purpose |
|---|---|---|
| CLI JSON output | step 2/3 | proves typed evidence |
| `report.json` + `report.md` | `results/<run>/` | reproducible evidence |
| Validator stdout line | Docker run | proves PASS with counterfactual |
| GUI screenshot | step 4 | proves reference flow label |
| `pytest -q` output | 248 passed, 6 skipped | proves test health |
| CI run URL | GitHub run #6 or newer | proves CI on dev |
| Independent benchmark hash | `Get-FileHash` | proves frozen benchmark |

## Optional demo (only if checkpoint exists)

- GUI `generated_flow` view with provider/checkpoint label.
- T5-generated workflow → plan → lab → evidence (must be honest that validator
  still uses a fixed marker unless changed).
- Stage-1 `metrics.json` with BLEU/ROUGE and exact epoch/precision.

## Never demo / never claim

- Never relabel the CAPEC reference flow as "T5-generated".
- Never claim 3 experts; only 1 advisor reviewer.
- Never compare 0,8594 or 0,7508 with paper's 0,7589 as if same protocol.
- Never say SBERT, stage 2, cve-002/003 or Docker CI are complete.
- Never claim dataset numbers verified from a clean clone.
- Never show a PASS from a simulated run.

## Rehearsal acceptance

- [ ] Full script runs twice consecutively with clean teardown.
- [ ] Every number shown has an artifact file behind it.
- [ ] Limitations slide is shown before Q&A, not hidden.
- [ ] Reviewer can answer: "What does T5 actually contribute today?" with "code + local toy run, not the paper-scale result".
