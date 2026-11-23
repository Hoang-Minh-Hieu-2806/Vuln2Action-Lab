# Post-Kaggle execution roadmap — Vuln2Action-Lab (2026-11-23)

## 0. Trạng thái run hiện tại

| Item | Value |
|---|---|
| Kaggle account | `ttalgies` (token mới `KGAT_bcdf...f158`, đã verify) |
| Dataset access | `dangthiet/vuln2action-p0-stage1` OK |
| Kernel | `ttalgies/vuln2action-paper-stage1-cve-only-target-fp32`, version 1 |
| URL | https://www.kaggle.com/code/ttalgies/vuln2action-paper-stage1-cve-only-target-fp32 |
| Cấu hình | t5-base, CVE-only, target đầy, FP32, lịch 50 epoch, dừng sau 5, 2×T4 DDP, max 512/512 |
| Quota lúc push | 10,21h remaining / 30h (reset 28/11) |
| Trạng thái kiểm tra cuối | **QUEUED**, log rỗng, GPU chưa bắt đầu tiêu |
| Kernel cũ | `phamquang0606/...` vẫn RUNNING; **không restart/cancel/push version mới** |

Lưu ý: quota thực tế là ~10h, không phải 18h như thông tin ban đầu. Run 5 epoch ước
~9–10h + eval → **sát ngưỡng**; notebook có checkpoint mỗi 693 step nên nếu cạn quota
vẫn còn artifact trung gian, nhưng có thể thiếu `metrics.json` cuối.

## 1. Khi kernel bắt đầu chạy (RUNNING)

- Đọc log, xác nhận 2 dòng đầu:
  - `cuda devices: 2` (nếu `0` hoặc `torch +cpu` → DỪNG, báo lỗi accelerator, không đốt quota).
  - `Cloning into ...` không kèm `Could not resolve host` (nếu lỗi DNS → Internet bị chặn trên account này; dừng).
- Ghi timestamp bắt đầu, quota còn lại.
- Không push version mới trong lúc chạy.

## 2. Khi kernel kết thúc

Lưu artifact thật (thư mục mới, không ghi đè):

```powershell
kaggle kernels output ttalgies/vuln2action-paper-stage1-cve-only-target-fp32 `
  -p data/external/stage1_ttalgies
```

Kiểm tra bắt buộc:
- `metrics.json`, `predictions.jsonl`, `training_config.json`, checkpoint tồn tại.
- `training_config.json`: `fp16=false/--no-fp16`, `num_train_epochs=50` (lịch), `stop_after_epoch=5` (thực), GPU=2×T4.
- Đếm số dòng `predictions.jsonl` (kỳ vọng 11.089); đếm prediction khác nhau để phát hiện collapse.
- SHA-256 checkpoint và metrics (ghi artifact hash).
- Nếu kernel bị kill do quota: giữ checkpoint cuối, ghi rõ **metrics không hoàn chỉnh**.

## 3. Cập nhật kết quả (chỉ khi có artifact)

- Điền `PENDING KAGGLE ARTIFACT` trong `docs/paper-deviation-report-vi.md` bằng số thật.
- Tick `README.md:87` (`T5 GPU training run and full evaluation`) **chỉ khi** có metrics đầy đủ.
- Viết `docs/t5-stage1-final-vi.md`: BLEU/ROUGE, epoch thực, precision, GPU, quota, config, hash, fail mode.
- Nhắc lại trong mọi bảng: 11.083/11.089 validation target trùng train → **không phải generalization**.
- So sánh riêng: CVE-only, gold-CAPEC-conditioned, hybrid. Không gộp với 0,8594/0,7508.

## 4. Quyết định nhánh kết quả

| Kết quả | Hành động |
|---|---|
| metrics hợp lệ, collapse giảm | Giữ làm kết quả CVE-only; chuyển T4 GUI wiring |
| metrics thấp/collapse như cũ | Giữ negative result; **không tăng epoch**; cân nhắc group-split trước khi nói generalization |
| kernel fail/quota cạn | T1 = BLOCKED; báo cáo dùng demo Level 1 + limitations |
| chỉ có checkpoint, không metrics | Ghi rõ thiếu eval; không tự tính BLEU |

## 5. Sau artifact — T4 GUI generated flow

- Chỉ khi có checkpoint hợp lệ: `gui/app.py` trả `reference_flow` + `generated_flow`
  + `generation` (provider/checkpoint/settings) + `generation_status`.
- Không có checkpoint → `generated_flow: null`, status `unavailable`; không giả output.
- Test: null-state và generated-state (`tests/unit/test_gui.py`).
- Owner: Integration; reviewer: Core.

## 6. T2 — khóa claims

- Bảng claim: VERIFIED / PARTIALLY VERIFIED / NOT VERIFIED / BLOCKED / NOT EVALUATED.
- Giữ nguyên: leakage 11.083/11.089, circular 120 CVE, independent 12/21, paper 0.7589,
  repo cũ 0.1640/0.2567, CAPEC-cond 0.8594, hybrid 0.7508/997.
- Không đổi số cũ cho đẹp; chỉ thêm số mới có artifact.

## 7. T3 — human evaluation (song song, không chờ Kaggle để chuẩn bị)

- Xin `splits.json` từ chủ dataset; đối chiếu `human_eval_20`.
- Sinh 20 workflow với provider/checkpoint đã chọn.
- Gửi `docs/human-evaluation/{protocol,reviewer-form}.md` cho 1 advisor.
- Chưa có → BLOCKED, không tự tạo case/điểm.

## 8. T8 — group-split (chỉ khi muốn nói generalization)

- Dùng `docs/evaluation/t5-group-split-plan.md`; tạo manifest group-disjoint, hash, overlap report.
- Không retrain trong đợt này nếu quota không cho phép.

## 9. T6 — Docker CI (tùy chọn)

- Assertions đã có local; bật job riêng sau một run GitHub-hosted xanh.
- Không `continue-on-error`, không bỏ qua counterfactual.

## 10. Final demo & freeze

- Rehearsal 2 lần: CLI rule-based `--execute --save` → PASS → evidence → GUI (có nhãn nguồn).
- Screenshot/log/artifact đóng gói (thư mục session mới, không ghi đè `artifacts/demo/cve-001/`).
- Freeze báo cáo sai lệch + Limitations slide trước Q&A.

## Critical path sau Kaggle

`kernel kết thúc → download artifact → verify metrics → điền report → T4 wiring → demo freeze`.

Song song không chờ Kaggle: `T2 claims`, `T3 xin split/advisor`, `T6 plan`.

**Rủi ro:** 10h quota cho 5 epoch là sát; nếu kernel bị kill, chỉ còn checkpoint —
không tự tính BLEU. Không rebuild graph hay đối chiếu `a152519` trong đợt này.
