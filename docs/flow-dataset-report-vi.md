# Báo cáo bước 3: execution-flow dataset

Ngày chạy: 2026-11-05  
Nhánh: `codex/paper-reproduction`  
Nguồn CAPEC đã chọn: `capec_predictions_word2vec_all.jsonl`  
Output: `data/processed/reproduction/flow_dataset/`

## 1. Cách dựng

Mỗi CVE trong train/validation được ghép với CAPEC tốt nhất do Word2Vec chọn.
Nếu CAPEC có `Execution_Flow`, các step được nhóm theo 3 pha của paper:

```text
Explore:  thu thập thông tin mục tiêu
Experiment: thử kỹ thuật / kiểm tra lỗ hổng
Exploit:  khai thác thành công
```

Mỗi row có 3 biến thể target để training script chọn theo ngân sách token:

| Field | Nội dung |
|---|---|
| `target` | phase + mô tả step + danh sách technique |
| `target_steps` | phase + mô tả step, bỏ technique |
| `target_techniques` | phase + tên technique, bỏ mô tả dài |

Ví dụ format:

```text
Explore: [Survey] ... (Techniques: spidering; proxy)
Experiment: [Test input] ... (Techniques: fuzzing)
Exploit: [Run code] ... (Techniques: union query)
```

`input` là mô tả CVE nguyên bản từ NVD. `phases` lưu cấu trúc step/technique
để dùng cho bước map ExploitDB và GUI.

## 2. Kết quả

| Hạng mục | Số lượng |
|---|---:|
| Tổng row train + validation | 30.077 |
| Train | 23.964 |
| Validation | 6.113 |
| CAPEC duy nhất | 174 |
| Row có đủ 3 pha | 25.484 (84,7%) |
| CVE không có CAPEC prediction | 15.793 |
| CVE có prediction nhưng CAPEC không có flow | 9.010 |
| Step trung bình / row | 4,03 |
| Technique trung bình / row | 5,75 |

Độ dài target (từ, chưa tokenize):

| Field | Trung bình | P90 |
|---|---:|---:|
| `target` | 258,6 | 521 |
| `target_steps` | 145,3 | 290 |
| `target_techniques` | 113,9 | 230 |

Vì target khá dài, cấu hình T5 nên dùng `max_target_length=256` cho
`target_techniques` hoặc `target_steps`; nếu dùng `target` đầy đủ thì nên
tăng lên 512. Cấu hình 128 token sẽ cắt mất nhiều flow; nếu vẫn muốn 128,
dùng `target_techniques` và chấp nhận truncation.

## 3. File đầu ra

```text
flow_dataset.jsonl      30.077 row đầy đủ
flow_train.jsonl        23.964 row
flow_validation.jsonl    6.113 row
flow_stats.json          số liệu và độ dài target
```

Các file nằm dưới `data/processed/reproduction/flow_dataset/` và đã git-ignore.

## 4. Cách tái lập

```bash
python scripts/build_flow_dataset.py \
  --dataset data/processed/reproduction \
  --predictions data/processed/reproduction/capec_selection/capec_predictions_word2vec_all.jsonl \
  --out data/processed/reproduction/flow_dataset
```

## 5. Sai lệch / giới hạn

- 15.793 CVE không có candidate CAPEC nên không có flow; nguyên nhân là
  CWE trực tiếp không có quan hệ CAPEC trong catalog hiện tại.
- 9.010 CVE có CAPEC nhưng CAPEC đó không có Execution Flow trong CAPEC 3.9.
- Chỉ 174 CAPEC khác nhau được dùng, nên flow dataset tập trung vào một phần
  catalog.
- Chưa làm stage 2 (enrich bằng ExploitDB) vì latest 55k chỉ khớp 27 dòng
  ExploitDB. Cần exploit-linked subset hoặc hybrid selection trước khi train
  stage 2 nghiêm túc.

## 6. Stage 2

?? map 665 technique sang 46.709 m? t? ExploitDB b?ng Word2Vec + cosine; xem
`docs/stage2-exploit-mapping-report-vi.md`. Dataset stage 2 n?m ?
`data/processed/reproduction/flow_dataset_stage2/`, target g?n
`target_exploit_techniques` d?i trung b?nh 37,4 t?.

## 7. Vi?c ti?p theo

1. Viết T5 training script stage 1 cho Kaggle T4 x2, có checkpoint/resume.
2. Chọn `target_techniques` + `max_target_length=256` hoặc `target` + 512.
3. Benchmark 1 epoch trên T4 trước khi chạy 50 epochs.
4. Sau đó xử lý riêng stage 2 / ExploitDB mapping.
