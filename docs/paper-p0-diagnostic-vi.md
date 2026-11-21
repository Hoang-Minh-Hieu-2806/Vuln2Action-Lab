# P0 diagnostic no-FP16 — T5 stage 1

Ngày chạy: 2026-11-13.

Kernel: `hoangdang1711/vuln2action-p0-diagnostic-no-fp16`

URL: https://www.kaggle.com/code/hoangdang1711/vuln2action-p0-diagnostic-no-fp16

## 1. Mục tiêu

Hai run P0 trước bị NaN sau epoch 1–2 và sinh prediction rỗng. Diagnostic này
giữ nguyên dữ liệu, target, độ dài và model, chỉ đổi **FP16 → FP32** để kiểm tra
xem lỗi có phải do mixed precision hay không.

## 2. Cấu hình

| Tham số | Giá trị |
|---|---|
| Dataset | stage 1, CVE-only, `target` full |
| Train rows | 16.000 (random, seed 42) |
| Validation rows | 1.000 (random, seed 43) |
| Model | `t5-base` |
| Max input / target | 512 / 512 |
| Batch / GPU | 4 |
| Gradient accumulation | 8 |
| Learning rate | `5e-5` |
| Epoch | 1 |
| Precision | **FP32 (`--no-fp16`)** |
| GPU | 2× T4 |
| Runtime | ~5.370 s (1h29m), trong đó train 2.053 s |

Đây là **diagnostic trên subset**, không phải kết quả paper. Không so sánh trực
tiếp với full 11.089 dòng.

## 3. Kết quả

| Metric | Giá trị |
|---|---:|
| Eval loss step 100 | 3,967 |
| Eval loss step 200 | 2,537 |
| Eval loss step 250 (epoch 1) | **2,414** |
| Sentence BLEU | **0,1468** |
| Corpus BLEU | 0,2192 |
| ROUGE-1 F1 | 0,3689 |
| ROUGE-2 F1 | 0,1677 |
| ROUGE-L F1 | 0,2630 |
| Prediction rỗng | **0/1.000** |

Prediction trung bình 341 từ; reference trung bình 290 từ. Mẫu prediction bắt
đầu bằng `Explore: ...` và có nội dung, không còn chuỗi rỗng.

## 4. Độ ổn định số học

Toàn bộ 15 log entry của `trainer_state.json` đều hữu hạn:

- `loss`: 201,4 → 80,2 → 58,0 → ... → 26,3.
- `grad_norm`: 231,7 ở step 20; sau đó giảm còn 7–14.
- Không có `nan`/`inf` ở `loss`, `grad_norm` hay `eval_loss`.
- Kết thúc đủ 250 step, lưu `final` bình thường.

So với run FP16 trước:

| | FP16 full | FP32 diagnostic |
|---|---|---|
| Eval loss epoch 1 | 6,941 | 2,414 (1.000 dòng) |
| Eval loss epoch 2 | NaN | không có (chỉ 1 epoch) |
| Grad norm | 500–1.130 rồi NaN | 7–232, hữu hạn |
| Prediction cuối | rỗng | 0/1.000 rỗng |

## 5. Kết luận

- **FP16 là nguyên nhân trực tiếp/ chính** của collapse trong P0; FP32 trên cùng
  kiểu dữ liệu, cùng target dài 512 và cùng model không bị NaN.
- Vẫn cần xác nhận trên **full 44.331 train**; diagnostic 16.000 dòng chỉ là
  bằng chứng định hướng.
- Không dùng BLEU `0,1468` làm số paper: đây là 1 epoch trên 36% train, khác
  protocol 10 epoch/44.331 dòng.
- FP32 chậm hơn đáng kể: ~7,9 example/s so với ~21 example/s của FP16. Full
  10 epoch ước tính ~15–16 giờ train thuần, cộng eval; có thể vượt giới hạn
  12 giờ/kernel và phải chia checkpoint hoặc chạy ít epoch hơn.

## 6. Việc tiếp theo

1. Thêm guard NaN để dừng sớm (đã thêm `--abort-on-nan` vào `scripts/train_t5.py`).
2. Sau khi quota reset (2026-11-14), chạy **full 44.331 train, FP32, 1 epoch**
   trước để có full-validation hợp lệ (~2 giờ).
3. Nếu ổn định, resume lên 10 epoch theo schedule 50 epoch; lưu checkpoint từng
   epoch để không mất kết quả nếu NaN.
4. Chỉ sau đó mới chạy stage 2; không dùng checkpoint FP16 đã hỏng.

## 7. File bằng chứng

- `data/external/paper_p0_diag/kernel_log_raw.txt`
- `data/external/paper_p0_diag/diag_stdout.txt`
- `data/external/paper_p0_diag/diag_no_fp16/training_config.json`
- `data/external/paper_p0_diag/diag_no_fp16/checkpoint-250/trainer_state.json`
- `data/external/paper_p0_diag/diag_no_fp16_eval1000/metrics.json`
- `data/external/paper_p0_diag/diag_no_fp16_eval1000/predictions.jsonl`
