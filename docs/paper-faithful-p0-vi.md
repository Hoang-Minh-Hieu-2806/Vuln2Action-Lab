# P0 — CVE-only two-stage T5 theo protocol paper

Tài liệu này ghi lại cấu hình P0 đang chạy trên Kaggle. P0 là **thí nghiệm
paper-faithful**, không dùng gold CAPEC và không trộn với hybrid appendix.

## 1. Protocol cố định

| Thành phần | Giá trị |
|---|---|
| Input | CVE description, không có CAPEC |
| Stage 1 target | `target` (full execution flow) |
| Stage 2 target | `target_exploit` (flow + mô tả ExploitDB) |
| Split | 44.331 train / 11.089 validation (80/20 theo CVE) |
| Model | `t5-base` |
| Max input / target | `512` / `512` |
| Optimizer | AdamW, LR `5e-5` |
| Schedule | `50` epoch, warmup 10% |
| Decode | beam `4` |
| Metrics | sentence-average BLEU + ROUGE-1/2/L |

Không có exploit source code trong dataset; chỉ description và metadata.

## 2. Dataset đã đưa lên Kaggle

- Stage 1: `hoangdang1711/vuln2action-p0-stage1`
  - `flow_train.jsonl`: 44.331 dòng
  - `flow_validation.jsonl`: 11.089 dòng
  - `flow_stats.json`
- Stage 2: `hoangdang1711/vuln2action-p0-stage2`
  - cùng split, thêm `target_exploit`
  - `technique_exploit_map.jsonl`

Dataset riêng tư; nguồn local là
`data/processed/reproduction/flow_dataset{,_stage2}/`.

## 3. Lần chạy đầu

Do GPU quota còn khoảng 13 giờ, lần chạy đầu là **10 epoch đầu của schedule
50 epoch**, không phải kết quả cuối cùng của paper. LR schedule vẫn được tính
cho 50 epoch, nên đây không phải một run 10-epoch độc lập.

- Stage 1: `notebooks/kaggle/paper_stage1_target/`
  - Kaggle id: `hoangdang1711/vuln2action-paper-stage1-cve-only-target`
  - Output: `t5_stage1_paper_target/`
- Stage 2: `notebooks/kaggle/paper_stage2_target_exploit/`
  - Kaggle id: `hoangdang1711/vuln2action-paper-stage2-cve-only-target-exploit`
  - Output: `t5_stage2_paper_target_exploit/`

Mỗi notebook:

1. Train đến epoch 10, checkpoint ở epoch 5 và 10.
2. Probe checkpoint 5/10 trên 1.000 dòng validation.
3. Evaluate **toàn bộ 11.089 dòng** bằng checkpoint cuối (epoch 10).

## 4. Trạng thái chạy

Cả hai kernel đã chạy xong nhưng **thất bại về mặt mô hình**:

- Stage 1: https://www.kaggle.com/code/hoangdang1711/vuln2action-paper-stage1-cve-only-target
- Stage 2: https://www.kaggle.com/code/hoangdang1711/vuln2action-paper-stage2-cve-only-target-exploit

Cả hai bị NaN từ sau epoch 1–2 và sinh prediction rỗng; full-validation BLEU
xấp xỉ 0. Chi tiết, log và hướng sửa nằm trong
[`paper-p0-results-vi.md`](paper-p0-results-vi.md). Không dùng các checkpoint
này cho stage 2, GUI hay báo cáo paper.

## 5. Cách đọc kết quả

- Chỉ số headline phải lấy từ thư mục `*_eval_full/metrics.json`.
- `bleu` là BLEU trung bình từng câu, thang 0–1.
- ROUGE-1/2/L lấy F1 để so sánh với Table 5 của paper.
- Kết quả 10 epoch chỉ là checkpoint probe; không được ghi là kết quả 50 epoch.
- Nếu resume, phải giữ nguyên schedule 50 epoch và checkpoint đã lưu; không
  chạy lại từ đầu với schedule khác.
- Stage 2 CVE-only không dùng CAPEC dự đoán. Kết quả hybrid vẫn chỉ nằm ở
  appendix và không được so trực tiếp với stage 2 CVE-only.

## 6. Sai lệch đã biết

- Chưa chạy đủ 50 epoch trong một session do giới hạn GPU.
- Chưa chạy FLAN-T5-base, TF-IDF variant, SBERT retrieval, GUI và human eval
  trong P0 này.
- CAPEC snapshot hiện tại không khớp số 1.024 trong paper; cần audit riêng.
