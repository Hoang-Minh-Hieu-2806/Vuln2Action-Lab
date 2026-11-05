# B?o c?o b??c 3: execution-flow dataset (114.560 CVE)

Ng?y ch?y: 2026-11-05  
Ngu?n CAPEC: `capec_predictions_word2vec_all.jsonl`  
Output: `data/processed/reproduction/flow_dataset/`

## 1. C?ch d?ng

M?i CVE train/validation ???c gh?p v?i CAPEC t?t nh?t do Word2Vec ch?n. N?u
CAPEC c? Execution Flow, c?c step ???c nh?m theo 3 pha:

```text
Explore:  thu th?p th?ng tin m?c ti?u
Experiment: th? k? thu?t / ki?m tra l? h?ng
Exploit:  khai th?c th?nh c?ng
```

M?i row c?:

| Field | N?i dung |
|---|---|
| `target` | phase + m? t? step + technique |
| `target_steps` | phase + m? t? step, b? technique |
| `target_techniques` | phase + technique, b? m? t? d?i |

`input` l? m? t? CVE NVD; `phases` gi? c?u tr?c step/technique cho stage 2/GUI.

## 2. K?t qu?

| H?ng m?c | S? l??ng |
|---|---:|
| T?ng row train + validation | **55.420** |
| Train | 44.331 |
| Validation | 11.089 |
| CAPEC duy nh?t | 176 |
| Row ?? 3 pha | 47.903 (86,4%) |
| CVE train/val kh?ng c? CAPEC prediction | 44.753 |
| CVE train/val c? prediction nh?ng CAPEC kh?ng c? flow | 14.267 |
| Step trung b?nh / row | 3,87 |
| Technique trung b?nh / row | 6,23 |

?? d?i target (t?, ch?a tokenize):

| Field | Trung b?nh | P90 |
|---|---:|---:|
| `target` | 286,6 | 521 |
| `target_steps` | 143,6 | 213 |
| `target_techniques` | 143,3 | 285 |

V?i `max_target_length=256`, `target_techniques`/`target_steps` g?n nh? v?a;
`target` ??y ?? n?n d?ng 512 n?u mu?n gi? to?n b? flow. N?u bu?c d?ng 128,
ch?p nh?n truncation ho?c d?ng target stage 2 g?n h?n.

## 3. File ??u ra

```text
flow_dataset.jsonl      55.420 row
flow_train.jsonl        44.331 row
flow_validation.jsonl   11.089 row
flow_stats.json
```

## 4. C?ch t?i l?p

```bash
python scripts/build_flow_dataset.py \
  --dataset data/processed/reproduction \
  --predictions data/processed/reproduction/capec_selection/capec_predictions_word2vec_all.jsonl \
  --out data/processed/reproduction/flow_dataset
```

## 5. Stage 2

?? map 665 technique sang 45.538 m? t? ExploitDB (1999?2023) b?ng Word2Vec +
cosine; xem `docs/stage2-exploit-mapping-report-vi.md`. Stage 2 n?m ?
`data/processed/reproduction/flow_dataset_stage2/`.

## 6. Gi?i h?n

- 44.753 CVE train/val kh?ng c? candidate CAPEC n?n kh?ng c? flow.
- 14.267 CVE train/val c? CAPEC nh?ng CAPEC kh?ng c? Execution Flow.
- Ch? 176 CAPEC ???c d?ng; flow t?p trung v?o m?t ph?n catalog.
- Ch?a train T5; dataset ?? s?n cho Kaggle.
