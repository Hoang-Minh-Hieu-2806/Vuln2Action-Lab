# T5 stage 1 evaluation - checkpoint-693

## 1. C?u h?nh ch?y

| H?ng m?c | Gi? tr? |
|---|---:|
| Kaggle kernel | `minhiw/vuln2action-t5-stage1-eval` |
| Checkpoint | `checkpoint-693` t? notebook benchmark |
| Split | validation |
| Rows | 11.089 |
| Target field | `target_techniques` |
| Max input / target | 256 / 256 |
| Batch size / beams | 8 / 4 |
| fp16 | C? |
| Tr?ng th?i | **COMPLETE** |

Notebook:

```text
notebooks/kaggle/stage1_eval/kaggle_t5_stage1_eval.ipynb
```

## 2. K?t qu?

| Metric | Gi? tr? |
|---|---:|
| BLEU (sacreBLEU, thang 0-100) | **37,55** |
| ROUGE-1 | 44,43% |
| ROUGE-2 | 31,70% |
| ROUGE-L | **38,53%** |

Tr?n subset reference kh?ng r?ng:

| Metric | Gi? tr? |
|---|---:|
| Rows | 9.509 |
| BLEU | 36,47 |
| ROUGE-1 | 50,26% |
| ROUGE-2 | 36,24% |
| ROUGE-L | 43,39% |

Kh?ng n?n so tr?c ti?p BLEU 37,55 v?i BLEU 0,7589 c?a paper v? kh?c
checkpoint, s? epoch, split v? c?ch t?nh.

## 3. C?nh b?o: validation b? tr?ng target v?i train

??y l? v?n ?? quan tr?ng h?n ?i?m s?:

- Validation c? **125 target flow kh?c nhau**.
- Train c? **139 target flow kh?c nhau**.
- **11.083 / 11.089** validation rows c? target ?? xu?t hi?n nguy?n v?n trong
  train; ch? **6 rows** c? target ho?n to?n ch?a th?y.
- Exact match to?n b?: **847 / 11.089 = 7,64%**.
- Exact match tr?n 9.509 rows c? reference kh?ng r?ng: **808 / 9.509 = 8,50%**.

V? split hi?n t?i chia theo CVE nh?ng target flow ???c t?i s? d?ng gi?a nhi?u
CVE/CAPEC, model g?n nh? ch? c?n h?c thu?c 139 flow m?u. Eval loss 0,4455 v?
BLEU 37,55 v? v?y **kh?ng ??i di?n cho kh? n?ng t?ng qu?t h?a**.

## 4. Model b? collapse

- 11.089 rows nh?ng ch? c? **19 prediction kh?c nhau**.
- Top 8 prediction chi?m **96,01%** s? rows.
- Prediction ph? bi?n nh?t xu?t hi?n **3.319 l?n**.
- 14,25% reference l? flow r?ng `Explore: Experiment: Exploit:`, nh?ng model
  ch? sinh ??ng flow r?ng 39 l?n.
- Nhi?u CVE kh?c nhau nh?n c?ng m?t flow generic (port mapping, spidering,
  buffer overflow, SQL injection).

??y l? d?u hi?u model ch?a h?c ???c ?nh x? CVE -> CAPEC -> flow, m? ?ang ch?n
m?t v?i template ph? bi?n.

## 5. ??i chi?u v?i paper g?c

Paper g?c d?ng ??ng b?i to?n:

```text
CVE description -> execution flow (Explore / Experiment / Exploit)
```

Paper **kh?ng** ??a CAPEC v?o input T5, kh?ng d?ng group split theo CAPEC, v?
chia 80% train / 20% validation theo CVE. V? v?y, ?? reproduction trung th?c,
pipeline ch?nh v?n gi? CVE-only input v? split 80/20 nh? paper.

H? qu? l? target overlap ? tr?n c?ng l? m?t h?n ch? c?a thi?t k? paper: model
c? th? ??t BLEU cao b?ng c?ch h?c flow template c?a CAPEC. Khi b?o c?o ph?i
n?u r? h?n ch? n?y, kh?ng ???c g?i 37,55 l? generalization.

Paper d?ng:

- BLEU trung b?nh t?ng c?u, thang 0-1 (Algorithm 2), kh?ng ph?i corpus BLEU.
- ROUGE-1/2/L v?i Precision, Recall, F1 (Table 5).
- 50 epoch, lr 5e-5, AdamW, cross-entropy, T5-base.

`scripts/evaluate_t5.py` ?? ???c s?a ?? xu?t:

- `bleu`: BLEU trung b?nh t?ng c?u (0-1), d?ng cho so s?nh paper.
- `bleu_corpus`: corpus BLEU (0-1), metric ph?.
- `rouge*_precision`, `rouge*_recall`, `rouge*_f1`.

## 6. K?t lu?n

- **K? thu?t:** pipeline ch?y ?n, ?? 11.089 rows, kh?ng l?i, sinh metrics v?
  predictions ??y ??.
- **Ch?t l??ng:** checkpoint 1 epoch ch?a ??; c?n ch?y ??ng c?u h?nh paper
  (T5-base, 50 epoch) r?i evaluate l?i b?ng metric paper.
- **H?n ch? c?n b?o c?o:** validation target g?n nh? tr?ng train; BLEU/ROUGE
  c?a split n?y l? upper-bound l?c quan.
- **Ki?m tra b? sung (kh?ng thay th? paper):** c? th? ch?y m?t th? nghi?m
  group split theo `capec_id` ?? ?o generalization th?t, nh?ng ph?i ghi r? ??
  l? th? nghi?m robustness, kh?ng ph?i c?u h?nh paper.

## 7. L?u ? khi b?o c?o

Ph?i ghi r?:

- ??y l? checkpoint 1 epoch, kh?ng ph?i 50 epoch;
- validation target g?n nh? tr?ng train;
- BLEU/ROUGE hi?n t?i l? **upper-bound l?c quan**, kh?ng ph?i generalization;
- ch? s? exact match v? s? unique prediction c?n ???c b?o c?o k?m BLEU/ROUGE.
