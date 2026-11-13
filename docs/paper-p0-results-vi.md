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

## 4. Nguyên nhân khả dĩ

Chưa có kết luận nhân quả tuyệt đối, nhưng thứ tự ưu tiên kiểm tra:

1. **FP16 overflow / loss-scale không ổn định** với T5-base, target dài
   (`512` token) và DDP 2 GPU. Đây là nghi phạm chính vì loss/grad norm tăng
   rồi thành NaN.
2. **Truncation 512** làm target rất dài; 12,3% target full dài hơn 512 từ.
   Cần kiểm tra sau khi đã ổn định số học.
3. **Target full quá dài/đa dạng** so với dữ liệu hiện có; không nên tăng
   epoch khi loss đang NaN.
4. Không thấy lỗi ở split: train/validation không trùng CVE; 44.331 + 11.089
   dòng, 0 overlap.

## 5. Quyết định

- **Không** ghi `~0` như kết quả paper và **không** so sánh với BLEU `0,7589`.
- **Không** chạy 50 epoch với cấu hình hiện tại.
- Quota còn khoảng **1,38 giờ** (thời điểm đọc kết quả); không đủ cho một run
  10 epoch đáng tin. Quota làm mới ngày 2026-11-14.
- Trước khi chạy lại, phải có một diagnostic ngắn:
  - 1 epoch, `--no-fp16` (hoặc chỉ dùng bf16 nếu có A100), cùng split;
  - lưu checkpoint ngay epoch 1, evaluate 1.000 dòng;
  - nếu loss hữu hạn và prediction không rỗng, mới thử lại fp16/lr;
  - thêm guard phát hiện NaN và dừng sớm thay vì chạy tiếp 8 epoch hỏng.
- Sau khi ổn định số học mới quyết định có dùng `target` full hay phải ghi rõ
  deviation sang `target_steps`.

## 6. File bằng chứng

Log đã tải về local (git-ignored):

- `data/external/paper_p0_stage1/kernel_log_raw.txt`
- `data/external/paper_p0_stage1/stage1_stdout.txt`
- `data/external/paper_p0_stage2/kernel_log_raw.txt`
- `data/external/paper_p0_stage2/stage2_stdout.txt`

Metric đầy đủ nằm trong log stdout; API `kernels output` đang timeout khi liệt
kê output lớn, nên chưa tải được `metrics.json`/`predictions.jsonl` riêng.
