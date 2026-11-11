# T5 stage 1 - ??nh gi? checkpoint epoch 10

## 1. K?t qu?

Notebook:

```text
minhiw/vuln2action-t5-stage1-paper-eval10
```

Checkpoint:

```text
checkpoint-6930 (epoch 10)
```

| Metric | Gi? tr? |
|---|---:|
| Rows | 11.089 |
| BLEU trung b?nh t?ng c?u (0-1) | **0,1640** |
| Corpus BLEU (0-1) | 0,2799 |
| ROUGE-1 Precision / Recall / F1 | 0,3899 / 0,5064 / 0,3553 |
| ROUGE-2 Precision / Recall / F1 | 0,2365 / 0,1845 / 0,1982 |
| ROUGE-L Precision / Recall / F1 | 0,3160 / 0,4235 / 0,2831 |

So v?i paper:

| Metric | Paper T5 | Hi?n t?i |
|---|---:|---:|
| BLEU | 0,7589 | 0,1640 |
| ROUGE-1 F1 | 0,8126 | 0,3553 |
| ROUGE-L F1 | 0,7950 | 0,2831 |

## 2. So v?i checkpoint 1 epoch

Checkpoint 1 epoch tr??c ??:

| Metric | 1 epoch | 10 epoch |
|---|---:|---:|
| BLEU trung b?nh t?ng c?u | 0,2792 | 0,1640 |
| Corpus BLEU | 0,4071 | 0,2799 |
| ROUGE-1 F1 | 0,4493 | 0,3553 |
| ROUGE-L F1 | 0,3950 | 0,2831 |
| Exact match | 847 / 11.089 (7,64%) | 209 / 11.089 (1,88%) |

**Train th?m epoch l?m k?t qu? x?u ?i**, n?n v?n ?? kh?ng ph?i ch? l? "ch?a ?? 50 epoch".

## 3. Model collapse

- 11.089 rows nh?ng ch? c? **25 prediction kh?c nhau**.
- Top 8 prediction chi?m **94,34%**.
- Prediction ph? bi?n nh?t chi?m **4.879 / 11.089 = 44,0%**.
- 14,25% reference l? flow r?ng `Explore: Experiment: Exploit:`, nh?ng model
  kh?ng sinh flow r?ng l?n n?o.
- Nhi?u CVE kh?c nhau nh?n c?ng flow spidering / web application.

## 4. Nguy?n nh?n ch?nh

L?n train n?y d?ng `target_techniques` - ch? g?m t?n technique, kh?ng g?m step
description. H? qu?:

- `target_techniques` r?ng ? **6.277 / 44.331** train rows (14,2%).
- Ch? c? **139** target kh?c nhau trong train.
- Model h?c ph?n ph?i target chung, kh?ng h?c ???c ?nh x? CVE -> flow.

Paper m? t? execution flow g?m c?c step v?i description v? technique. V? v?y
c?n train tr?n `target` (full execution flow), kh?ng ph?i `target_techniques`.

## 5. ?? s?a th?m

- `scripts/train_t5.py`: m?c ??nh **kh?ng** reload checkpoint c? eval loss th?p
  nh?t; gi? epoch cu?i gi?ng paper. Tr??c ?? `final/` b? quay v? epoch 1 d?
  train 10 epoch.
- ?ang ch?y pilot 1 epoch v?i `target` full flow, `max_target_length=512`,
  batch 4/GPU, gradient accumulation 8.
- N?u pilot cho BLEU/ROUGE t?t h?n r? r?t, m?i ch?y 10/50 epoch tr?n target
  ??ng.

## 6. K?t lu?n

- **K? thu?t:** eval full ch?y xong, metric paper-style ??y ??.
- **Ch?t l??ng:** ch?a ?n; k?m xa paper v? k?m h?n checkpoint 1 epoch.
- **Kh?ng n?n ch?y 50 epoch ngay** v?i `target_techniques`.
- Ph?i s?a target sang full execution flow tr??c; sau ?? m?i ??nh gi? l?i.
