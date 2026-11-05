# B?o c?o b??c 2: ch?n CAPEC t?t nh?t (dataset 114.560 CVE)

Ng?y ch?y: 2026-11-05  
Dataset: `data/processed/reproduction/` (114.560 CVE stratified 2002?2023)  
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

| Ph??ng ph?p | C? candidate | Candidate recall | Top-1 ??ng | Accuracy /100 | Accuracy tr?n CVE c? candidate |
|---|---:|---:|---:|---:|---:|
| TF-IDF | 87 | 87 | 86 | 86,0% | 98,85% |
| Word2Vec | 87 | 87 | **87** | **87,0%** | **100,0%** |

Paper b?o c?o **89/100**. B?n ??y ?? n?y ??t **87/100**, k?m paper 2 CVE.
Trong 87 CVE c? candidate, Word2Vec ch?n ??ng c? 87. 13 CVE c?n l?i kh?ng c?
candidate n?n kh?ng th? tr? l?i.

Word2Vec th?ng TF-IDF 87 so v?i 86, ph? h?p k?t lu?n paper ch?n Word2Vec.

## 3. To?n b? 114.560 CVE

| H?ng m?c | S? l??ng |
|---|---:|
| CVE | 114.560 |
| C? candidate | 69.791 |
| C? reference CVE2CAPEC kh?ng r?ng | 80.807 |
| V?a candidate v?a reference | 69.504 |
| Top-1 ??ng | 68.052 |
| Accuracy tr?n to?n b? | 59,40% |
| Accuracy tr?n CVE tr? l?i ???c | **97,91%** |
| Candidate recall | 85,46% |

Con s? 59,40% b? k?o xu?ng b?i c?c CVE kh?ng c? candidate; accuracy tr?n CVE
tr? l?i ???c l? 97,91%.

## 4. So v?i b?n 55k

B?n 55k ??t 88/100; b?n ??y ?? 114.560 ??t 87/100. Ch?nh l?ch 1 CVE l? nhi?u
c?a split 100 CVE, kh?ng ph?i suy gi?m ph??ng ph?p. B?n ??y ?? c? candidate
coverage th?p h?n m?t ch?t (87/100 so v?i 91/100), n?n tr?n accuracy th?p h?n.

## 5. File ??u ra

```text
capec_selection/capec_predictions_tfidf_capec_eval_100.jsonl
capec_selection/capec_predictions_word2vec_capec_eval_100.jsonl
capec_selection/capec_selection_metrics_capec_eval_100.json
capec_selection/capec_predictions_word2vec_all.jsonl
capec_selection/capec_selection_metrics_all.json
```

## 6. Gi?i h?n

- 13/100 CVE eval kh?ng c? candidate CAPEC do CWE tr?c ti?p kh?ng c? quan h?
  trong CAPEC 3.9.
- Catalog CAPEC 3.9 c? 615 entry, ?t h?n 1.024 c?a paper; CWE 4.20 c? 969 entry.
- Kh?ng leo CWE cha ?? t?o candidate, v? paper d?ng quan h? CWE?CAPEC tr?c ti?p.
