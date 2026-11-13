# Kết quả P0 — hai stage T5 CVE-only

Ngày đọc kết quả: 2026-11-13.

## 1. Trạng thái

Cả hai kernel Kaggle đã `COMPLETE`:

- Stage 1: `hoangdang1711/vuln2action-paper-stage1-cve-only-target`
- Stage 2: `hoangdang1711/vuln2action-paper-stage2-cve-only-target-exploit`

Tuy nhiên **kết quả không dùng được**: model bị NaN/collapse, prediction rỗng.
Đây là negative result, không phải kết quả paper-faithful.

## 2. Metric full validation

Cả hai chạy full **11.089 dòng validation**, beam 4, `target`/`target_exploit`.

| Run | Rows | BLEU | Corpus BLEU | ROUGE-1 F1 | ROUGE-2 F1 | ROUGE-L F1 |
|---|---:|---:|---:|---:|---:|---:|
| Stage 1 `target` | 11.089 | ~1,55e-18 | 0,0 | 0,0 | 0,0 | 0,0 |
| Stage 2 `target_exploit` | 11.089 | ~1,55e-18 | 0,0 | 0,0 | 0,0 | 0,0 |

Checkpoint 5 và 10 trên 1.000 dòng cũng chỉ có BLEU ~`5,24e-25` và ROUGE
`0,0`. Prediction mẫu là chuỗi rỗng, ví dụ `PRED: ,`.

## 3. Dấu hiệu lỗi huấn luyện

| Run | Eval loss epoch 1 | Eval loss epoch 2+ | Train loss cuối | Runtime |
|---|---:|---:|---:|---:|
| Stage 1 | 6,941 | NaN | 16,82 | ~20.870 s |
| Stage 2 | 6,759 | NaN từ epoch 3 | 22,56 | ~20.680 s |

Log cho thấy loss/grad norm rất lớn ngay đầu:

- `loss` khoảng 244–256, `grad_norm` khoảng 500–1.130.
- Stage 1 có `grad_norm: nan` từ khoảng epoch 1,5; sau đó loss về 0 và
  `eval_loss` NaN.
- Stage 2 cũng có `grad_norm: nan` và loss 0 từ khoảng epoch 2,2.
- Việc `train_loss` cuối là 16,82/22,56 là trung bình méo, vì nhiều bước sau
  đã NaN/0.

Vì vậy BLEU `~0` **không phải model học kém bình thường**, mà là checkpoint
cuối đã hỏng; decoder chỉ sinh EOS/rỗng.

## 4. Diagnostic no-FP16 (đã chạy)

Sau khi thấy nghi phạm FP16, đã chạy một diagnostic **FP32** trên 16.000 train
và 1.000 validation, cùng `target`, cùng max length 512, 1 epoch:

| Metric | FP32 diagnostic |
|---|---:|
| Eval loss epoch 1 | 2,414 |
| Sentence BLEU | 0,1468 |
| ROUGE-1 F1 | 0,3689 |
| ROUGE-2 F1 | 0,1677 |
| ROUGE-L F1 | 0,2630 |
| Prediction rỗng | 0/1.000 |

Loss và grad norm **hữu hạn hoàn toàn**, không có NaN. Đây là bằng chứng mạnh
rằng FP16 là nguyên nhân chính của collapse. Kết quả này chỉ là diagnostic trên
subset/1 epoch, **không dùng làm số paper**. Chi tiết:
[`paper-p0-diagnostic-vi.md`](paper-p0-diagnostic-vi.md).

## 5. Nguyên nhân khả dĩ

Diagnostic FP32 xác nhận **FP16 là nguyên nhân chính**; các yếu tố dữ liệu
vẫn cần kiểm tra trên full train:

1. **FP16 overflow / loss-scale không ổn định** với T5-base, target dài
   (`512` token) và DDP 2 GPU. Diagnostic FP32 không còn NaN, nên đây là
   nguyên nhân chính.
2. **Truncation 512** làm target rất dài; 12,3% target full dài hơn 512 từ.
   Cần kiểm tra sau khi đã ổn định số học.
3. **Target full quá dài/đa dạng** so với dữ liệu hiện có; không nên tăng
   epoch khi loss đang NaN.
4. Không thấy lỗi ở split: train/validation không trùng CVE; 44.331 + 11.089
   dòng, 0 overlap.

## 6. Quyết định

- **Không** ghi `~0` như kết quả paper và **không** so sánh với BLEU `0,7589`.
- **Không** chạy 50 epoch với cấu hình FP16 hiện tại.
- Diagnostic FP32 đã chạy xong và ổn định; quota GPU hiện đã dùng hết
  (`30,12h/30h`), làm mới ngày 2026-11-14.
- Việc tiếp theo sau khi quota reset:
  - chạy **full 44.331 train, FP32, 1 epoch** trước để có full-validation hợp lệ;
  - nếu ổn định, resume lên 10 epoch theo schedule 50 epoch;
  - lưu checkpoint từng epoch và dùng `--abort-on-nan` (đã thêm) để dừng sớm;
  - không dùng checkpoint FP16 đã hỏng cho stage 2.

## 7. File bằng chứng

Log đã tải về local (git-ignored):

- `data/external/paper_p0_stage1/kernel_log_raw.txt`
- `data/external/paper_p0_stage1/stage1_stdout.txt`
- `data/external/paper_p0_stage2/kernel_log_raw.txt`
- `data/external/paper_p0_stage2/stage2_stdout.txt`
- `data/external/paper_p0_diag/diag_no_fp16_eval1000/metrics.json`
- `data/external/paper_p0_diag/diag_no_fp16_eval1000/predictions.jsonl`

Metric đầy đủ nằm trong log stdout; API `kernels output` đang timeout khi liệt
kê output lớn, nên chưa tải được `metrics.json`/`predictions.jsonl` riêng cho
hai run P0 full. Riêng diagnostic FP32 đã tải được metric và prediction.
