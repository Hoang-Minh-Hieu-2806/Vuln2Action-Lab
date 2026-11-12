# Hybrid hai tầng: CVE → CAPEC → execution flow

Tài liệu này mô tả hướng **operational extension** cho Vuln2Action. Đây không
phải kết quả CVE-only đúng paper, mà là pipeline hai tầng để tránh dùng gold
CAPEC lúc inference.

## Kiến trúc

```text
CVE description
      │
      ▼
┌──────────────────────────────┐
│ Tầng 1: CVE → CAPEC          │
│ Word2Vec / TF-IDF + cosine   │
└──────────────────────────────┘
      │  selected CAPEC + score
      ▼
┌──────────────────────────────┐
│ Tầng 2: CAPEC + CVE → flow   │
│ T5-base, CAPEC-conditioned   │
└──────────────────────────────┘
      │
      ▼
Explore: ...
Experiment: ...
Exploit: ...
```

- Tầng 1 chỉ dùng CVE description và candidate CAPEC từ CWE.
- Tầng 2 dùng CAPEC **do tầng 1 dự đoán**, không dùng gold CAPEC.
- Nếu không có candidate hoặc CAPEC không có execution flow, pipeline phải
  fallback về CVE-only hoặc trả trạng thái “không đủ dữ kiện”.

## Vì sao cần hai bộ evaluation

`flow_dataset` được tạo bằng chính selector Word2Vec. Vì vậy nếu đánh giá
hybrid trên các nhãn đó, `capec_id` dự đoán sẽ trùng gần như 100% với nhãn
dataset. Đó là **in-distribution check**, không đo chất lượng selection.

Hai nhóm view:

| View | Input CAPEC | Target flow | Mục đích |
|---|---|---|---|
| `common_predicted` | CAPEC dự đoán | flow của nhãn dataset | So sánh trực tiếp với baseline/common 1.000 |
| `reference_gold` | CAPEC reference | flow của CAPEC reference | Upper bound tầng 2 trên nhãn độc lập |
| `reference_predicted` | CAPEC dự đoán | flow hợp lệ từ reference | End-to-end thực tế |
| `reference_predicted_correct` | CAPEC dự đoán | flow của chính CAPEC đó | Tầng 2 khi selection đúng |
| `reference_cve_only` | không có | flow reference | Lower bound CVE-only trên cùng target |

Với `reference_predicted`, nếu CAPEC dự đoán nằm trong tập reference thì target
là flow của CAPEC dự đoán; nếu không, target là một flow reference hợp lệ. Như
vậy điểm end-to-end phản ánh cả lỗi chọn CAPEC và lỗi sinh flow.

## Tạo dataset evaluation

```bash
python scripts/build_hybrid_eval.py \
  --base-dataset data/processed/reproduction/flow_dataset_eval_common1000 \
  --out data/processed/reproduction/hybrid_eval \
  --limit 1000
```

Tập random 1.000 CVE từ validation:

```bash
python scripts/build_hybrid_eval.py \
  --base-dataset data/processed/reproduction/flow_dataset \
  --out data/processed/reproduction/hybrid_eval_random1000 \
  --limit 20000 \
  --sample-size 1000 \
  --seed 42
```

Mỗi view có `flow_validation.jsonl`, dùng trực tiếp với `scripts/evaluate_t5.py`.

## Chạy evaluation

Ví dụ:

```bash
python scripts/evaluate_t5.py \
  --checkpoint <capec-conditioned-checkpoint> \
  --dataset data/processed/reproduction/hybrid_eval_random1000/reference_predicted \
  --target-field target_steps \
  --include-capec \
  --output-dir outputs/hybrid/reference_predicted
```

CVE-only lower bound:

```bash
python scripts/evaluate_t5.py \
  --checkpoint <cve-only-checkpoint> \
  --dataset data/processed/reproduction/hybrid_eval_random1000/reference_cve_only \
  --target-field target_steps \
  --no-include-capec \
  --output-dir outputs/hybrid/reference_cve_only
```

## Kết quả

Kernel evaluation:

```text
minhiw/vuln2action-hybrid-eval
```

Kết quả sẽ được cập nhật sau khi kernel hoàn tất.

## Giới hạn

- CAPEC 3.9 công khai chỉ có 239 entry có execution flow; không thể tái tạo
  1.024 CAPEC của paper.
- Một CVE có thể map tới nhiều CAPEC; chọn một reference flow duy nhất chỉ là
  xấp xỉ, không phải ground truth duy nhất.
- Nếu selector không có candidate, pipeline không thể sinh flow có CAPEC
  conditioning.
- Không có exploit code nào được lưu hoặc đưa vào evaluation; chỉ dùng mô tả
  flow và metadata.
