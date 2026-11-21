# B?o c?o dataset paper-faithful ??y ?? (114.560 CVE)

Ng?y ch?y: 2026-11-05  
Nh?nh: `feature/paper-reproduction`  
Output ch?nh: `data/processed/reproduction/`  
B?n 55k c? ???c gi? t?i `data/processed/reproduction_55k/`.

## 1. Quy?t ??nh ch?n dataset

Paper g?c d?ng corpus l?ch s? ??n h?t 2023 v? join ExploitDB 1999?2023.
B?n ch?nh v? v?y d?ng ??ng quy m? CVE c?a paper:

- CVE NVD 2002?2023.
- ExploitDB ch? l?y `date_published` trong 1999?2023.
- L?y **114.560 CVE** stratified theo n?m, seed 42.
- Kh?ng d?ng CVE2CAPEC ?? train; ch? evaluation.

L?nh build:

```bash
python scripts/build_reproduction_dataset.py \
  --target-cves 114560 --seed 42 --selection-strategy stratified \
  --start-year 2002 --end-year 2023 \
  --exploit-start-year 1999 --exploit-end-year 2023 \
  --out-dir data/processed/reproduction
```

## 2. S? li?u

| H?ng m?c | S? l??ng |
|---|---:|
| CVE NVD raw 2002?2023 | 234.395 |
| CVE ???c ch?n | **114.560** |
| CVE c? CWE | 89.311 |
| CVE-CWE pairs | 96.368 |
| CVE-CWE pairs c? trong catalog hi?n t?i | 89.572 |
| Candidate rows c? CAPEC | 73.127 |
| CVE2CAPEC reference rows | 112.428 |
| CVE2CAPEC reference c? CAPEC | 80.807 |
| ExploitDB rows 1999?2023 | 45.538 |
| ExploitDB rows kh?p CVE ???c ch?n | **13.161** |
| Train / validation | 91.552 / 22.888 |
| CAPEC eval / human eval | 100 / 20 |

Audit: `ok: true`; c?n warning v? 6.796 CVE-CWE rows d?ng CWE deprecated
trong NVD c? (CWE-264, CWE-399, CWE-310, ...). Kh?ng remap sang CWE hi?n ??i.

## 3. So v?i paper

| H?ng m?c | Paper | B?n n?y |
|---|---:|---:|
| CVE | 114.560 | **114.560** |
| CVE-CWE | 28.831 | 96.368 |
| CWE-CAPEC | 46.575 | 1.212 c?p catalog duy nh?t |
| CWE | 915 | 969 |
| CAPEC | 1.024 | 615 |
| ExploitDB | 1999?2023 | 1999?2023, 13.161 d?ng kh?p |

S? CVE ?? b?ng paper. C?c kh?c bi?t c?n l?i n?m ? catalog CWE/CAPEC hi?n t?i
(CWE 4.20, CAPEC 3.9), c?ch ??m CWE?CAPEC, v? vi?c paper kh?ng c?ng b? dataset
g?c. Kh?ng tuy?n b? tr?ng t?ng d?ng v?i paper.

## 4. H? qu?

- Dataset ?? quy m? CVE ?? ch?y CAPEC selection, flow dataset, stage 1/2 v? GUI.
- ExploitDB c? 13.161 d?ng kh?p, t?t h?n nhi?u so v?i 27 d?ng c?a b?n latest
  2026 v? 6.474 d?ng c?a b?n 55k.
- T5 training s? n?ng h?n: 91.552 train rows v? 22.888 validation rows.
- B?n 55k v?n gi? ? `data/processed/reproduction_55k/` ?? so s?nh ho?c ch?y
  th? nhanh.
- B?n latest 2026 v?n gi? ? `data/processed/reproduction_latest/`.
