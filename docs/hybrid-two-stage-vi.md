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
vậy điểm end-to-end phản ánh cả lỗi chọn CAPEC và lỗi sinh flow. Đây là phép đo
**strict**: nếu selector chọn một CAPEC hợp lệ khác với CAPEC reference được
chọn làm target, flow đúng cho CAPEC đó vẫn bị phạt. Vì vậy cần đọc kèm
`reference_predicted_correct` và selection accuracy.

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

## Độ phủ end-to-end

Các view `reference_*` chỉ đánh giá được trên CVE có CAPEC reference và CAPEC
đó có execution flow. Đây là **flow-eligible subset**, không phải toàn bộ
114.560 CVE:

| Hạng mục | Số lượng |
|---|---:|
| Tổng CVE | 114.560 |
| Có candidate CAPEC | 69.791 |
| Chọn được CAPEC | 69.504 (trong 80.807 CVE có reference) |
| CVE reference được chọn đúng | 68.052 |
| Selected CAPEC không có execution flow | 14.267 |
| Flow rows dùng được | 55.420 |
| Train / validation flow rows | 44.331 / 11.089 |
| Coverage flow-eligible | 48,4% (55.420 / 114.560) |

Vì vậy BLEU/ROUGE của hybrid phải được đọc cùng coverage. Với CVE không có
candidate hoặc CAPEC không có flow, hệ thống phải fallback CVE-only; điểm
hybrid không đại diện cho 100% CVE.

## Kết quả

Kernel evaluation:

```text
minhiw/vuln2action-hybrid-eval
```

Kernel dùng ba nguồn:

```text
dataset: minhiw/vuln2action-hybrid-eval-bundle
model:   minhiw/vuln2action-t5-stage1-capec-conditioned
model:   minhiw/vuln2action-t5-stage1-target-steps-pilot
```

Do quota GPU của `minhiw` gần hết, lần chạy hoàn chỉnh được chuyển sang tài
khoản `hoangdang1711`:

```text
kernel:  hoangdang1711/vuln2action-hybrid-eval
dataset: hoangdang1711/vuln2action-hybrid-capec-model   # CAPEC model + eval views
dataset: hoangdang1711/vuln2action-hybrid-cve-model     # CVE-only model
```

Cả hai dataset đều private; chỉ chứa model weights và mô tả/flow, không có
exploit source.

Các view được evaluate:

```text
common_predicted
random_reference_gold
random_reference_predicted
random_reference_predicted_correct
random_reference_cve_only
```

Kết quả:

| Thiết lập | Input lúc inference | Rows | BLEU | ROUGE-1 F1 | ROUGE-L F1 | Exact |
|---|---|---:|---:|---:|---:|---:|
| Hybrid end-to-end, random reference | predicted CAPEC + CVE | 997 | **0,7508** | 0,8258 | **0,7919** | 628 |
| Hybrid, selection đúng (stage-2 conditional) | predicted CAPEC + CVE | 977 | 0,7639 | 0,8352 | 0,8030 | 628 |
| Reference-flow input, random reference | reference CAPEC + CVE | 997 | 0,4831 | 0,6601 | 0,5874 | 165 |
| CVE-only, cùng target reference | CVE description | 997 | 0,0190 | 0,1358 | 0,1262 | 0 |
| Common predicted (in-distribution) | predicted CAPEC + CVE | 1.000 | 0,8594 | 0,9058 | 0,8840 | 801 |
| CVE-only baseline, common 1.000 | CVE description | 1.000 | 0,2567 | 0,4887 | 0,3686 | 100 |

Đọc bảng này phải tách ba thiết lập:

- **Hybrid end-to-end** `0,7508` là kết quả thật với CAPEC do selector dự đoán.
  Trên 997 rows, selector khớp independent reference ở **977/997 = 97,99%**;
  20 rows còn lại bị phạt bởi target reference fallback.
- **Stage-2 conditional** `0,7639` chỉ tính 977 rows selection đúng; đây là
  mức trần thực tế của tầng sinh flow khi CAPEC đã đúng.
- **Reference-flow input** `0,4831` **không phải upper bound**. Nó thấp hơn
  hybrid vì 112/997 target CAPEC reference không có trong train; model không
  học được flow của các CAPEC hiếm. Chỉ `common` có CAPEC đã thấy mới đạt
  `0,8594`; con số này là in-distribution, không phải kết quả độc lập.
- **CVE-only** trên cùng target reference chỉ `0,0190`; model suy giảm mạnh,
  chỉ 26/997 output có đủ ba phase. Đây là lower bound, không phải baseline
  paper-faithful.

`0,8594` **không phải** kết quả CVE-only và không so trực tiếp với BLEU
`0,7589` của paper. Paper dùng CVE-only với khoảng 1.024 CAPEC; kết quả hybrid
này dùng predicted CAPEC và chỉ 182 CAPEC có flow trong dataset hiện tại.

Các chỉ số cấu trúc:

| View | Có đủ 3 phase | Exact | Unique prediction |
|---|---:|---:|---:|
| `common_predicted` | 1.000/1.000 | 801/1.000 | 64 |
| `random_reference_predicted` | 991/997 | 628/997 | 133 |
| `random_reference_gold` | 996/997 | 165/997 | 28 |
| `random_reference_cve_only` | 26/997 | 0/997 | 437 |

CVE-only trên target reference bị degenerate: 437 output khác nhau nhưng chỉ
26 output có đủ `Explore/Experiment/Exploit`, và mẫu đầu tiên lặp
`Exploit: [Survey the vulnerability]` nhiều lần. Vì vậy `0,0190` phản ánh cả
việc thiếu CAPEC conditioning lẫn lỗi repetition; không nên dùng nó làm đại
diện cho CVE-only paper-faithful (baseline đó là `0,2567` trên common set).

## Giới hạn

- CAPEC 3.9 công khai chỉ có 239 entry có execution flow; không thể tái tạo
  1.024 CAPEC của paper.
- Một CVE có thể map tới nhiều CAPEC; chọn một reference flow duy nhất chỉ là
  xấp xỉ, không phải ground truth duy nhất.
- Nếu selector không có candidate, pipeline không thể sinh flow có CAPEC
  conditioning.
- Không có exploit code nào được lưu hoặc đưa vào evaluation; chỉ dùng mô tả
  flow và metadata.
