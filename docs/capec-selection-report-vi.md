# Báo cáo bước 2: chọn CAPEC tốt nhất

Ngày chạy: 2026-11-05  
Nhánh: `codex/paper-reproduction`  
Dataset: `data/processed/reproduction/` (55.000 CVE mới nhất)  
Ground truth: CVE2CAPEC, chỉ dùng cho evaluation.

## 1. Phương pháp

Đầu vào của mỗi CVE:

1. lấy tất cả dòng `cve_capec_candidates.jsonl` của CVE đó;
2. hợp các `candidate_capec_ids` lại (một CVE có thể có nhiều CWE);
3. so mô tả CVE với mô tả từng CAPEC ứng viên;
4. chọn CAPEC có cosine similarity cao nhất.

Text của CAPEC là `name + description`; text của CVE là `description`.
Không dùng CVE2CAPEC trong lúc chọn, chỉ dùng để chấm điểm.

### TF-IDF

- `TfidfVectorizer` với unigram + bigram, `sublinear_tf=True`, stopword list
  chung của repo.
- Fit vocabulary trên toàn bộ mô tả CVE + mô tả CAPEC, sau đó vector hóa
  query và các CAPEC.
- Cosine similarity, chọn top-1 trong tập ứng viên.

### Word2Vec

- Skip-gram (`sg=1`), `vector_size=100`, `window=5`, `min_count=1`,
  `epochs=10`, `workers=1`, `seed=42`.
- Huấn luyện trên token của toàn bộ mô tả CVE + CAPEC.
- Vector câu = trung bình vector các từ; chuẩn hóa L2; cosine similarity.
- Chọn top-1 trong tập ứng viên.

Các tham số Word2Vec là lựa chọn reproduction; paper không công bố đầy đủ
siêu tham số.

## 2. Kết quả trên 100 CVE evaluation

Split `capec_eval_100` có 100 CVE, tất cả đều có reference CVE2CAPEC không rỗng.

| Phương pháp | Có candidate | Candidate recall | Top-1 đúng | Accuracy /100 | Accuracy trên CVE có candidate | Cosine trung bình của CAPEC được chọn |
|---|---:|---:|---:|---:|---:|---:|
| TF-IDF | 80 | 80 | 78 | **78,0%** | **97,5%** | 0,0289 |
| Word2Vec | 80 | 80 | 78 | **78,0%** | **97,5%** | 0,8320 |

Điểm quan trọng: 20 CVE không có candidate CAPEC nào, nên trần accuracy của
split này là 80/100. Trong 80 CVE có candidate, hai phương pháp chọn đúng 78,
tức 97,5%. Hai CVE còn lại chọn sai.

Hai phương pháp hòa nhau về top-1 trên split nhỏ này. Paper chọn Word2Vec vì
similarity cao hơn; bản reproduction cũng dùng **Word2Vec** cho bước sinh flow
về sau. Không nên so trực tiếp cosine trung bình ở bảng trên với con số
"max similarity" 52,9% / 91,2% của paper vì paper báo cáo đại lượng khác.

## 3. Kết quả trên toàn bộ 55.000 CVE

Chạy Word2Vec cho toàn bộ dataset:

| Hạng mục | Số lượng |
|---|---:|
| CVE | 55.000 |
| CVE có candidate CAPEC | 39.181 |
| CVE có reference CVE2CAPEC không rỗng | 48.127 |
| CVE vừa có candidate vừa có reference | 38.581 |
| Top-1 đúng | 38.374 |
| Accuracy trên toàn bộ 55k | 69,77% |
| Accuracy trên CVE trả lời được | 99,46% |
| Candidate recall | 80,02% |

Con số 69,77% bị kéo xuống bởi các CVE không có candidate; đây không phải
"model chọn sai" mà là giới hạn của candidate generation từ CWE–CAPEC trực tiếp.
Báo cáo tách riêng accuracy trên CVE trả lời được để tránh gây hiểu nhầm.

## 4. So với paper

| Hạng mục | Paper | Reproduction | Ghi chú |
|---|---:|---:|---|
| CAPEC accuracy trên 100 CVE | 89/100 | 78/100 | Candidate recall của bản này chỉ 80/100 |
| Accuracy trên CVE có candidate | Không báo cáo | 97,5% | 78/80 |
| Phương pháp được chọn | Word2Vec | Word2Vec | Cùng top-1 với TF-IDF ở split này |
| CAPEC catalog | 1.024 | 615 | Dùng CAPEC 3.9 hiện có |
| CWE–CAPEC | 46.575 | 1.212 cặp catalog duy nhất | Cách đếm khác paper |

Không tuyên bố đạt 89/100. Chênh lệch chủ yếu do candidate coverage: 20 CVE
không có CAPEC ứng viên vì CWE trực tiếp của chúng không có quan hệ CAPEC trong
catalog hiện tại. Đã kiểm tra: phần lớn là CWE-416, CWE-787, CWE-863, CWE-266,
CWE-639 và một số CWE khác. Không tự động leo lên CWE cha để tạo candidate vì
paper dùng quan hệ CWE–CAPEC trực tiếp; nếu muốn tăng coverage, đó phải là một
thí nghiệm riêng và được báo cáo như một deviation.

## 5. File đầu ra

Nằm trong `data/processed/reproduction/capec_selection/` và đã git-ignore:

```text
capec_predictions_tfidf_capec_eval_100.jsonl
capec_predictions_word2vec_capec_eval_100.jsonl
capec_selection_metrics_capec_eval_100.json
capec_predictions_word2vec_all.jsonl
capec_selection_metrics_all.json
```

Mỗi dòng prediction có:

- `cve_id`
- `method`
- `selected_capec_id`
- `score`
- `candidate_capec_ids`
- `reference_capec_ids` (evaluation only)
- `correct`

## 6. Cách tái lập

```bash
# So sánh TF-IDF và Word2Vec trên 100 CVE
python scripts/select_capec.py --dataset data/processed/reproduction \
  --method both --scope eval --split capec_eval_100

# Sinh CAPEC đã chọn cho toàn bộ 55k CVE (dùng cho bước flow dataset)
python scripts/select_capec.py --dataset data/processed/reproduction \
  --method word2vec --scope all
```

Word2Vec cần `gensim`:

```bash
pip install -e ".[nlp]"
```

## 7. Việc tiếp theo

1. Sinh execution-flow dataset từ CAPEC đã chọn.
2. Map flow sang 3 pha Explore / Experiment / Exploit.
3. Tạo train/validation cho T5 stage 1 và stage 2.
4. Viết training script T4 x2 có checkpoint/resume cho Kaggle.
