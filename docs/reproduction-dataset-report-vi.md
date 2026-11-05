# Báo cáo bước 1: Dataset reproduction

Ngày chạy: 2026-11-05  
Nhánh: `codex/paper-reproduction`  
Mục tiêu: tái lập phần dataset của paper Vuln2Action, lấy khoảng một nửa
quy mô CVE của paper (55.000 thay vì 114.560).

## 1. Kết quả tổng quan

| Hạng mục | Số lượng |
|---|---:|
| CVE thô lấy từ NVD 2002–2023 | 234.395 |
| CVE được chọn (stratified theo năm) | 55.000 |
| CVE có ít nhất một CWE | 42.897 |
| CVE có CVSS | 54.871 |
| CVE có CPE | 54.028 |
| Cặp CVE–CWE | 46.265 |
| Cặp CVE–CWE có CWE còn tồn tại trong catalog hiện tại | 43.038 |
| Cặp CWE–CAPEC duy nhất | 1.212 |
| Dòng candidate CAPEC theo từng cặp CVE–CWE | 46.265 |
| Dòng candidate có ít nhất một CAPEC | 35.125 |
| Tổng liên kết candidate CAPEC | 425.413 |
| CVE có reference CVE2CAPEC | 53.962 |
| ExploitDB metadata rows | 46.709 |
| ExploitDB rows khớp CVE trong sample | 6.546 |
| CWE catalog | 969 (CWE 4.20) |
| CAPEC catalog | 615 (CAPEC 3.9) |

Split đã tạo, không trùng lặp:

| Split | Số CVE |
|---|---:|
| Train | 43.904 |
| Validation | 10.976 |
| CAPEC evaluation | 100 |
| Human evaluation | 20 |

Tổng 4 split = 55.000 CVE.

## 2. Phân bố CVE được chọn theo năm CVE ID

| Năm | CVE |
|---:|---:|
| 1999 | 390 |
| 2000 | 277 |
| 2001 | 370 |
| 2002 | 528 |
| 2003 | 353 |
| 2004 | 620 |
| 2005 | 1.086 |
| 2006 | 1.641 |
| 2007 | 1.515 |
| 2008 | 1.644 |
| 2009 | 1.155 |
| 2010 | 1.191 |
| 2011 | 1.090 |
| 2012 | 1.289 |
| 2013 | 1.461 |
| 2014 | 1.979 |
| 2015 | 1.905 |
| 2016 | 2.200 |
| 2017 | 3.466 |
| 2018 | 3.799 |
| 2019 | 3.778 |
| 2020 | 4.553 |
| 2021 | 5.306 |
| 2022 | 6.208 |
| 2023 | 7.196 |

Sampling được thực hiện theo từng file NVD năm, tỷ lệ thuận với số CVE thô,
seed cố định `42`. Vì NVD annual feed 2002 chứa cả một số CVE ID cũ
(1999–2001), bảng theo năm CVE ID không trùng khớp tuyệt đối với năm file NVD.

## 3. Kiểm tra nhanh chất lượng candidate CAPEC

Đây **chưa phải** bước chọn CAPEC tốt nhất của paper. Đây chỉ là kiểm tra
xem tập candidate có chứa ít nhất một CAPEC mà CVE2CAPEC coi là đúng hay không.

| Tập | Có reference | Có candidate | Candidate chứa CAPEC đúng | Tỷ lệ |
|---|---:|---:|---:|---:|
| CAPEC eval 100 | 100 | 68 | 68 | 68,0% |
| Human eval 20 | 20 | 12 | 12 | 60,0% |
| Toàn bộ CVE có reference | 53.962 | — | 33.200 | 61,5% |

Con số 68/100 là **candidate recall**, không phải accuracy 89/100 của paper.
Bước 2 (TF-IDF/Word2Vec + cosine similarity) mới là bước chọn CAPEC tốt nhất.

## 4. Sai lệch so với paper

| Điểm | Paper | Bản reproduction | Ghi chú |
|---|---:|---:|---|
| CVE | 114.560 | 55.000 | Theo yêu cầu lấy khoảng một nửa |
| CWE | 915 | 969 | Dùng CWE 4.20 hiện có |
| CAPEC | 1.024 | 615 | Dùng CAPEC 3.9 hiện có |
| Cặp CVE–CWE | 28.831 | 46.265 | NVD hiện có nhiều CWE hơn |
| Cặp CWE–CAPEC | 46.575 | 1.212 | Paper có thể đếm theo mapping instance; bản này đếm cặp catalog duy nhất |
| Nguồn CVE | 1999–2023 | 2002–2023 | NVD 2.0 annual feed không có 1999–2001 |
| CAPEC tốt nhất | Có | Chưa | Thuộc bước 2 |

### CWE cũ / deprecated

3.227 dòng CVE–CWE dùng các CWE cũ không còn trong CWE 4.20, ví dụ:

- CWE-264: 1.258
- CWE-310: 597
- CWE-399: 595
- CWE-189: 261
- CWE-255: 182

Các dòng này được giữ nguyên nhãn gốc và đánh dấu `cwe_in_catalog: false`.
Không tự động đổi sang CWE mới vì sẽ tạo nhãn nhân tạo. Hệ quả là các dòng này
không sinh được candidate CAPEC nếu catalog hiện tại không có quan hệ tương ứng.

## 5. File đầu ra

Tất cả nằm trong `data/processed/reproduction/` và đã được git-ignore:

```text
cves.jsonl                     55.000 CVE
cwe.json                       CWE catalog + quan hệ cha/con + CAPEC
capec.json                     CAPEC catalog + Execution Flow
cve_cwe.jsonl                  46.265 cặp CVE–CWE
cwe_capec.jsonl                1.212 cặp CWE–CAPEC
cve_capec_candidates.jsonl      candidate CAPEC cho từng cặp CVE–CWE
cve2capec_reference.jsonl       reference chỉ dùng cho evaluation
exploitdb.jsonl                 metadata ExploitDB, không có source code
splits.json                    train/validation/eval splits
stats.json                     toàn bộ số liệu và version catalog
```

## 6. Cách tái lập

```bash
python scripts/download_reproduction_data.py --source all --start-year 2002 --end-year 2023
python scripts/build_reproduction_dataset.py --target-cves 55000 --seed 42
python scripts/audit_reproduction_dataset.py --dataset data/processed/reproduction
```

## 7. Việc tiếp theo

1. Chọn CAPEC tốt nhất bằng TF-IDF/Word2Vec + cosine similarity.
2. Sinh execution flow từ CAPEC đã chọn.
3. Tạo dataset T5 hai stage và training script cho Kaggle T4 x2.
4. Đánh giá candidate/selection trên 100 CVE và so với CVE2CAPEC.
