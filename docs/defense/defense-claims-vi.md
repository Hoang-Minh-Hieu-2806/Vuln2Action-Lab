# Defense claims — Vuln2Action-Lab

Ba nhóm claim dưới đây là cách nói thống nhất cho toàn bộ nhóm khi bảo vệ. Mọi câu đều
phải có artifact backing. Không thêm kết luận vượt quá bằng chứng.

## Claim 1 — T5 observed validation

Câu nói thống nhất:

"Mô hình T5 Stage 1 đạt BLEU 0.4802 và ROUGE-L F1 0.5659 trên tập validation 11.089 mẫu. Đây là observed validation result của lần chạy thực nghiệm, không phải bằng chứng độc lập về khả năng tổng quát hóa."

Bằng chứng:

- `data/external/resume_cp3465/t5_stage1_resume_cp3465_eval_full/metrics.json`
- `data/external/resume_cp3465/v2a-stage1-resume-checkpoint-3465.log`
- `data/external/resume_cp3465/t5_stage1_resume_cp3465/checkpoint-4158/trainer_state.json`
- `docs/t5-stage1-final-vi.md`

Không được nói: independent evaluation, generalization proven, paper-comparable result.

## Claim 2 — Leakage

Câu nói thống nhất:

"Có 11.083 trên 11.089 mẫu validation bị overlap với training data. Vì vậy, kết quả có nguy cơ bị ảnh hưởng đáng kể bởi leakage và nhóm không sử dụng nó để khẳng định mô hình tổng quát hóa trên CVE chưa từng gặp."

Bằng chứng hiện có:

- `reports/definition-of-done.md` — dòng leakage statement.
- `docs/defense/limitations-slide.md` — dòng 31 và 44.
- `docs/paper-deviation-report-vi.md` — dòng 61, 67, 99, 124, 129.
- Nguồn dữ liệu được trích dẫn trong các tài liệu trên là split/dataset hiện có; nhóm
  **không tự tái kiểm toán overlap trong Final Defense Gate**.

Trạng thái bằng chứng: số liệu leakage là giá trị đã được ghi nhận trong hồ sơ nghiên cứu.
Cần đối chiếu thêm với split manifest gốc nếu hội đồng yêu cầu kiểm chứng độc lập.

## Claim 3 — Demo semantics

Câu nói thống nhất:

"Demo hiện tại sử dụng luồng SIMULATED. Flow hiển thị trong GUI là reference flow, không phải kết quả được T5 sinh ra trong lần chạy demo."

Bằng chứng:

- `artifacts/demo/final-cve001-20261123T065251Z/consistency.json`
- `artifacts/demo/final-cve001-20261123T065251Z/evidence/report.json`
- `artifacts/demo/final-cve001-20261123T065251Z/validator/validation.json`
- `artifacts/demo/final-cve001-20261123T065251Z/screenshots/`
- `gui/app.py`, `gui/templates/index.html`, `tests/unit/test_gui.py`
- `reports/execution/post-kaggle-research-closure-report.md`
- `python scripts/verify_demo_freeze.py` → `DEMO FREEZE VERDICT: PASS`

Không được dùng các cụm sau:

- `T5 generated this demo`
- `Live Docker exploitation`
- `Full paper reproduction`
- `Generalization proven`
- `Demo PASS` khi chỉ có `SIMULATED`

## Claim audit

| Claim | Current wording | Evidence | Correct wording | File and line | Status |
|---|---|---|---|---|---|
| T5 observed validation | "BLEU 0,4802; ROUGE-L F1 0,5659... observed validation, leakage 11,083/11,089, không generalization" | `metrics.json`, kernel log, `docs/t5-stage1-final-vi.md` | Giữ nguyên | `docs/paper-deviation-report-vi.md:99`; `docs/defense/limitations-slide.md:30-32` | ALIGNED |
| Leakage | "not generalization, not independent evaluation"; "không chứng minh generalization" | leakage statements in research docs | Giữ nguyên; không tự tái kiểm toán | `docs/defense/limitations-slide.md:31,44`; `docs/paper-deviation-report-vi.md:61,67` | ALIGNED |
| Demo semantics | "SIMULATED", "reference flow", "Docker lab validation not run" | frozen demo artifacts + verifier + GUI source | Giữ nguyên | `docs/defense/limitations-slide.md:15-22`; `docs/defense/demo-script-vi.md`; `reports/defense/rehearsal-01.md` | ALIGNED |
| Forbidden phrase scan | Only negated forms found ("not full paper reproduction", "không chứng minh generalization") | grep over `docs/defense/`, `README.md`, `reports/` | Không cần sửa | scan at Final Defense Gate | NO CONTRADICTION FOUND |

Không có sửa hàng loạt. Không có tài liệu nào bị chỉnh trong Phase 3.
