# B?o c?o b??c 2: ch?n CAPEC t?t nh?t (dataset paper-faithful)

Ng?y ch?y: 2026-11-05  
Dataset: `data/processed/reproduction/` (55k stratified 2002?2023)  
Ground truth: CVE2CAPEC, ch? d?ng cho evaluation.

## 1. Ph??ng ph?p

- Candidate CAPEC = h?p c?c candidate t? m?i CVE?CWE row c?a CVE.
- So m? t? CVE v?i `name + description` c?a t?ng CAPEC candidate.
- TF-IDF: unigram + bigram, `sublinear_tf`, cosine.
- Word2Vec: skip-gram, 100 chi?u, window 5, 10 epoch, seed 42, vector c?u =
trung b?nh vector t?, cosine.
- Kh?ng d?ng CVE2CAPEC khi ch?n; ch? d?ng ?? ch?m top-1.

L?nh:

```bash
python scripts/select_capec.py --dataset data/processed/reproduction \
  --method both --scope eval --split capec_eval_100
python scripts/select_capec.py --dataset data/processed/reproduction \
  --method word2vec --scope all
```

## 2. K?t qu? 100 CVE evaluation

| Ph??ng ph?p | C? candidate | Candidate recall | Top-1 ??ng | Accuracy /100 | Accuracy tr?n CVE c? candidate | Cosine trung b?nh |
|---|---:|---:|---:|---:|---:|---:|
| TF-IDF | 91 | 90 | 87 | 87,0% | 95,6% | 0,0299 |
| Word2Vec | 91 | 90 | **88** | **88,0%** | **96,7%** | 0,8400 |

Paper b?o c?o **89/100**. B?n n?y ??t **88/100** v?i Word2Vec, s?t paper h?n
h?n b?n latest tr??c ?? (78/100). Trong 91 CVE c? candidate, Word2Vec ch?n ??ng
88; 9 CVE c?n l?i kh?ng c? candidate n?n kh?ng th? tr? l?i.

Word2Vec th?ng TF-IDF 88 so v?i 87, ph? h?p k?t lu?n paper ch?n Word2Vec.
Cosine trung b?nh c?a Word2Vec (0,84) c?ng g?n kho?ng 0,84?0,94 m? paper m? t?
cho c?c b??c/flow, nh?ng kh?ng n?n so tr?c ti?p v?i ?max similarity?.

## 3. To?n b? 55k

| H?ng m?c | S? l??ng |
|---|---:|
| CVE | 55.000 |
| C? candidate | 33.539 |
| C? reference CVE2CAPEC kh?ng r?ng | 38.837 |
| V?a candidate v?a reference | 33.402 |
| Top-1 ??ng | 32.720 |
| Accuracy tr?n to?n b? | 59,49% |
| Accuracy tr?n CVE tr? l?i ???c | **97,96%** |
| Candidate recall | 85,49% |

Con s? 59,49% b? k?o xu?ng b?i c?c CVE kh?ng c? candidate; accuracy tr?n CVE tr?
l?i ???c l? 97,96%.

## 4. V? sao t?t h?n b?n latest

B?n latest 2026 c? 20/100 CVE kh?ng c? candidate v? ch? ??t 78/100. B?n
paper-faithful 2002?2023 c? 91/100 CVE c? candidate, candidate recall 90/100,
n?n top-1 ??t 88/100. ??y l? l? do ch?n corpus l?ch s? thay v? newest.

## 5. File ??u ra

```text
capec_selection/capec_predictions_tfidf_capec_eval_100.jsonl
capec_selection/capec_predictions_word2vec_capec_eval_100.jsonl
capec_selection/capec_selection_metrics_capec_eval_100.json
capec_selection/capec_predictions_word2vec_all.jsonl
capec_selection/capec_selection_metrics_all.json
```

## 6. Gi?i h?n

- 9/100 CVE eval kh?ng c? candidate CAPEC do CWE tr?c ti?p kh?ng c? quan h?
  trong CAPEC 3.9.
- Catalog CAPEC 3.9 c? 615 entry, ?t h?n 1.024 c?a paper; CWE 4.20 c? 969 entry.
- Kh?ng leo CWE cha ?? t?o candidate, v? paper d?ng quan h? CWE?CAPEC tr?c ti?p.
