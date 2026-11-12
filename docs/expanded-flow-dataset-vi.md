# Mở rộng flow dataset theo hướng CVE-only

## 1. Mục tiêu

Giữ nguyên input của T5 là **CVE description**, không đưa CAPEC vào input.
Chỉ mở rộng tập CVE có target flow để tăng số row và số CAPEC/flow khác nhau.

## 2. Cách làm

Script:

```text
scripts/build_expanded_flow_dataset.py
```

Quy trình:

1. Giữ nguyên split CVE trong `splits.json`.
2. Với CVE đã có selected CAPEC và CAPEC đó có `Execution_Flow`, giữ nguyên
   row cũ. Vì vậy 55.420 row baseline không bị thay đổi.
3. Với CVE chưa có flow, lấy candidate từ `cve2capec_reference.jsonl`, chỉ giữ
   CAPEC có `Execution_Flow`.
4. Nếu có nhiều candidate, dùng Word2Vec cosine giữa CVE description và
   `name + description` của CAPEC để chọn một CAPEC.
5. Sinh lại `target`, `target_steps`, `target_techniques` bằng đúng logic cũ.

Lệnh chạy:

```bash
python scripts/build_expanded_flow_dataset.py \
  --out data/processed/reproduction/flow_dataset_expanded
```

## 3. Kết quả

| Hạng mục | Dataset cũ | Dataset mở rộng |
|---|---:|---:|
| Rows | 55.420 | **80.477** |
| Train | 44.331 | **64.388** |
| Validation | 11.089 | **16.089** |
| CAPEC unique | 176 | **187** |
| CAPEC có flow trong catalog | 239 | 239 |
| Row đủ 3 phase | 47.903 (86,4%) | **70.461 (87,6%)** |
| `target_steps` mean / P90 | 143,6 / 213 | **136,9 / 213** |
| `target` mean / P90 | 286,6 / 521 | **267,4 / 447** |

Thêm được **25.057 CVE** có flow, nhưng chỉ thêm **11 CAPEC unique** so với
baseline. Nguyên nhân: Word2Vec thường chọn các CAPEC phổ biến như CAPEC-62,
CAPEC-44, CAPEC-478 cho nhiều CVE mới.

Trong reference có 216 CAPEC có flow; sau khi chọn còn **32 CAPEC reference
không được chọn**. Muốn tăng diversity lên gần 219 CAPEC cần thêm quota hoặc
rarity penalty khi chọn candidate.

## 4. Giới hạn

- Không thể đạt 1.024 CAPEC: CAPEC 3.9 chỉ có 615 entry, 239 entry có flow.
- 20 CAPEC có flow không xuất hiện trong cả reference lẫn selection hiện tại.
- Dataset mở rộng vẫn dùng chung flow cho nhiều CVE; BLEU có thể tăng nhưng
  chưa chắc tiến gần paper.
- CVE2CAPEC reference chỉ dùng để tạo target, không dùng làm input T5.

## 5. Hướng tiếp theo

1. Train lại `target_steps` trên dataset mở rộng, giữ nguyên CVE-only.
2. Đánh giá trên toàn bộ 16.089 validation rows.
3. So sánh với baseline 55.420 rows.
4. Nếu các CAPEC phổ biến vẫn chiếm ưu thế, thêm quota/rarity penalty để tăng
   diversity hoặc dùng class-balanced sampling.
