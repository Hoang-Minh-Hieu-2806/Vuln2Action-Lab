# Kịch bản demo bảo vệ — Vuln2Action-Lab

Kịch bản này chỉ dùng artifact đã freeze:

- Demo run ID: `final-cve001-20261123T065251Z`.
- Artifact root: `artifacts/demo/final-cve001-20261123T065251Z/`.
- Verifier: `python scripts/verify_demo_freeze.py`.
- Verdict: `SIMULATED`.
- Provider: `rule_based`.
- GUI flow: reference flow, không phải T5-generated.

Không tạo run mới trong kịch bản này. Không gọi output mô phỏng là `PASS` của Docker.

## Step 1 — Introduction

Nói ngắn:

- Hệ thống nhận một CVE hoặc mô tả lỗ hổng, truy xuất ngữ cảnh CWE/CAPEC,
  tạo workflow có cấu trúc, lập kế hoạch chạy lab cô lập và đóng gói evidence.
- Input demo: CVE mẫu `CVE-2024-0001` từ fixture local, đã lưu tại
  `artifacts/demo/final-cve001-20261123T065251Z/input/sample_cves.json`.
- Output mong đợi: evidence bundle + report JSON/Markdown + provenance + validator
  artifact + screenshot.
- Phạm vi: chứng minh luồng engineering chạy được ở chế độ `SIMULATED`; không chứng
  minh khai thác thật, không chứng minh T5 sinh flow trong demo này.

## Step 2 — CVE input

Chỉ ra file input đã freeze:

- `input/sample_cves.json` — CVE mẫu, có nhãn SAMPLE/fake.
- `input/lab.yaml` và `input/docker-compose.yml` — lab `cve-001` used as reference.

Nếu chạy lại CLI an toàn từ repo root:

```powershell
vuln2action --list-samples
vuln2action --sample CVE-2024-0001 --json-only
```

Expected output tối thiểu:

- `result.status = SIMULATED`.
- `provider = rule_based`.
- `evidence.generation`, `evidence.workflow`, `evidence.plan` có mặt.
- `evidence.checkpoint_id = null`.

Không tự thêm thông tin chưa có trong artifact.

## Step 3 — Retrieval

Giải thích từ artifact/provenance:

- Retrieval backend trong provenance: `semantic`.
- Context sources: `CWE-79`, `CWE-352`, và reference metadata
  `reference:https://example.com/fake-advisory-0001`.
- CWE mô tả lớp lỗi; CAPEC mô tả pattern tấn công; dữ liệu tham chiếu giúp chọn
  execution flow.
- Đây là dữ liệu tham chiếu cho workflow, không phải output T5-generated.

Evidence: `evidence/provenance.json`, `evidence/report.json`.

## Step 4 — Workflow

Mở:

- `workflow/workflow.json`
- `workflow/plan.json`

Giải thích 5 stage: `lab-up`, `inspect`, `probe`, `validate`, `teardown`.
Validator đảm bảo verdict chỉ đến từ lab validator có kiểm tra marker và counterfactual.

Nói rõ:

- GUI hiện có `reference_flow`, `generated_flow=null`, `generation_status=unavailable`.
- `flow` trong API là alias tương thích của `reference_flow`.
- Không được nói CAPEC reference flow là T5-generated.

Evidence: `gui/app.py`, `gui/templates/index.html`, `tests/unit/test_gui.py`.

## Step 5 — Validation

Hiển thị artifact đã freeze:

- `validator/validation.json`: `status = SIMULATED`.
- `logs/cli-exit.txt`: `0`.
- `logs/cli-stderr.log`: rỗng.
- `consistency.json`: `all_pass = true`.

Không tự tạo kết quả PASS. Nếu chưa chạy Docker lab thật, nói:

"Validator artifact ở đây là kết quả simulation đã freeze; Docker validation chưa hoàn thành."

## Step 6 — Evidence

Mở lần lượt:

- `evidence/evidence.json`
- `evidence/provenance.json`
- `evidence/report.json`
- `evidence/report.md`
- `hashes/SHA256SUMS.txt`
- `screenshots/cli-console.png`
- `screenshots/report-md.png`

Chạy:

```powershell
python scripts/verify_demo_freeze.py
```

Expected banner: `DEMO FREEZE VERDICT: PASS`, `sha256_entries=14 verified`.

## Step 7 — Limitations

Kết thúc bằng các câu bắt buộc:

- Demo verdict là `SIMULATED`.
- GUI đang hiển thị reference flow, không phải T5-generated output trong lần chạy demo.
- Docker validation chưa hoàn thành; không nói live exploitation hoặc PASS thật.
- Stage 1 BLEU 0.4802 / ROUGE-L F1 0.5659 là observed validation result, có leakage
  11,083/11,089; không phải generalization hoặc paper reproduction.
- T3 human evaluation, T6 Docker CI, T8 group-split và full checkpoint weights là
  outstanding work, đã được chủ dự án yêu cầu bỏ qua trong giai đoạn này.
