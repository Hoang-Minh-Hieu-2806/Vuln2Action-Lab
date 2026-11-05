# B?o c?o dataset paper-faithful (55k)

Ng?y ch?y: 2026-11-05  
Nh?nh: `codex/paper-reproduction`  
Output ch?nh: `data/processed/reproduction/`  
B?n latest c? ???c gi? t?i `data/processed/reproduction_latest/`.

## 1. Quy?t ??nh ch?n dataset

Paper g?c d?ng corpus l?ch s? ??n h?t 2023 v? join ExploitDB 1999?2023,
kh?ng d?ng ?newest CVE?. B?n ch?nh v? v?y quay l?i:

- CVE NVD 2002?2023.
- ExploitDB ch? l?y `date_published` trong 1999?2023.
- L?y 55.000 CVE stratified theo n?m, seed 42 (m?t n?a paper 114.560).
- Kh?ng d?ng CVE2CAPEC ?? train; ch? evaluation.

L?nh build:

```bash
python scripts/build_reproduction_dataset.py \
  --target-cves 55000 --seed 42 --selection-strategy stratified \
  --start-year 2002 --end-year 2023 \
  --exploit-start-year 1999 --exploit-end-year 2023 \
  --out-dir data/processed/reproduction
```

## 2. S? li?u

| H?ng m?c | S? l??ng |
|---|---:|
| CVE NVD raw 2002?2023 | 234.395 |
| CVE ???c ch?n | 55.000 |
| CVE c? CWE | 42.897 |
| CVE-CWE pairs | 46.265 |
| Candidate rows | 46.265 |
| Candidate rows c? CAPEC | 35.125 |
| CVE2CAPEC reference rows | 53.962 |
| CVE2CAPEC reference c? CAPEC | 38.837 |
| ExploitDB rows 1999?2023 | 45.538 |
| ExploitDB rows kh?p CVE ???c ch?n | **6.474** |
| Train / validation | 43.904 / 10.976 |
| CAPEC eval / human eval | 100 / 20 |

Audit: `ok: true`; ch? c?n warning v? CWE deprecated trong NVD c?
(CWE-264, CWE-310, CWE-399, ...). Kh?ng remap sang CWE hi?n ??i.

## 3. So v?i paper

| H?ng m?c | Paper | B?n n?y |
|---|---:|---:|
| CVE | 114.560 | 55.000 (m?t n?a) |
| CVE-CWE | 28.831 | 46.265 |
| CWE-CAPEC | 46.575 | 1.212 c?p catalog duy nh?t |
| CWE | 915 | 969 |
| CAPEC | 1.024 | 615 |
| ExploitDB | 1999?2023 | 1999?2023, 6.474 d?ng kh?p |

Kh?c bi?t ch?nh l? s? CVE b?ng m?t n?a, catalog CWE/CAPEC d?ng b?n hi?n t?i
(CWE 4.20, CAPEC 3.9), v? c?ch ??m CWE?CAPEC kh?c paper. Kh?ng tuy?n b? tr?ng s?
li?u paper.

## 4. H? qu?

- B?n n?y ph? h?p ?? ch?y CAPEC selection, flow dataset, stage 1/2 v? GUI.
- ExploitDB c? 6.474 d?ng kh?p, ?? ?? l?m pilot cho stage 2/SBERT, nh?ng v?n
  ?t h?n paper v? sample ch? 55k.
- B?n latest 2026 v?n gi? ? `data/processed/reproduction_latest/` ?? so s?nh,
  nh?ng kh?ng c?n l? dataset ch?nh.
