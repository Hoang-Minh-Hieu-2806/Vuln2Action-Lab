# Báo cáo bước 1: Dataset reproduction

Ngày chạy: 2026-11-05  
Nhánh: `codex/paper-reproduction`  
Mục tiêu: tái lập phần dataset của paper Vuln2Action, lấy khoảng một nửa
quy mô CVE của paper (55.000 thay vì 114.560).

Bản đang dùng là **latest mode**: chọn 55.000 CVE mới nhất theo ngày
`published` của NVD, thay vì sample đều theo năm. Bản paper-faithful
(stratified 2002–2023) vẫn được giữ ở
`data/processed/reproduction_paper_2023/`.

## 1. Kết quả tổng quan

| Hạng mục | Số lượng |
|---|---:|
| CVE thô lấy từ NVD 2002–2026 | 400.558 |
| CVE được chọn (55k mới nhất theo ngày publish) | 55.000 |
| CVE có ít nhất một CWE | 49.650 |
| CVE có CVSS | 51.562 |
| CVE có CPE | 18.402 |
| Cặp CVE–CWE | 57.023 |
| Cặp CVE–CWE có CWE còn tồn tại trong catalog hiện tại | 56.881 |
| Cặp CWE–CAPEC duy nhất | 1.212 |
| Dòng candidate CAPEC theo từng cặp CVE–CWE | 57.023 |
| Dòng candidate có ít nhất một CAPEC | 43.921 |
| Tổng liên kết candidate CAPEC | 419.052 |
| CVE có reference CVE2CAPEC (kể cả rỗng) | 54.203 |
| CVE có reference CVE2CAPEC thực sự có CAPEC | 48.127 |
| ExploitDB metadata rows | 46.709 |
| ExploitDB rows khớp CVE trong sample | 27 |
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
| 2010 | 1 |
| 2011 | 1 |
| 2012 | 4 |
| 2013 | 5 |
| 2014 | 9 |
| 2015 | 7 |
| 2016 | 11 |
| 2017 | 10 |
| 2018 | 2 |
| 2019 | 8 |
| 2020 | 17 |
| 2021 | 28 |
| 2022 | 33 |
| 2023 | 73 |
| 2024 | 134 |
| 2025 | 538 |
| 2026 | 54.119 |

Tổng = 55.000 CVE.

Việc chọn theo `published` (không theo năm trong CVE ID) là có chủ đích:
một số CVE ID cũ được NVD publish/update trong 2026 nên vẫn nằm trong nhóm
mới nhất. Vì vậy bảng theo năm CVE ID không trùng tuyệt đối với năm publish.

Nguồn NVD 2026 là annual feed hiện có tại thời điểm chạy (đến 2026-11-05),
nên đây là "mới nhất trong dữ liệu đã tải", không phải toàn bộ năm 2026.

## 3. Kiểm tra nhanh chất lượng candidate CAPEC

Đây **chưa phải** bước chọn CAPEC tốt nhất của paper. Đây chỉ là kiểm tra
xem tập candidate có chứa ít nhất một CAPEC mà CVE2CAPEC coi là đúng hay không.

| Tập | Có reference không rỗng | Có candidate | Candidate chứa CAPEC đúng | Tỷ lệ |
|---|---:|---:|---:|---:|
| CAPEC eval 100 | 100 | 80 | 80 | 80,0% |
| Human eval 20 | 16 | 14 | 14 | 70,0% (14/20) |
| Toàn bộ CVE có reference | 48.127 | — | 38.510 | 80,02% |

Trong 54.203 dòng reference CVE2CAPEC, có 6.076 dòng rỗng (không có CAPEC);
các dòng này bị loại khỏi mẫu số candidate recall.
Với 16 CVE human eval có reference, candidate recall là 14/16 = 87,5%.
Con số 80/100 là **candidate recall**, không phải accuracy 89/100 của paper.
Bước 2 (TF-IDF/Word2Vec + cosine similarity) mới là bước chọn CAPEC tốt nhất.

Kiểm tra lại bằng script:

```bash
python scripts/evaluate_candidate_recall.py --dataset data/processed/reproduction
```

## 4. Cảnh báo: độ phủ ExploitDB rất thấp

Trong 55.000 CVE mới nhất, chỉ **27 dòng ExploitDB** khớp CVE (27 CVE duy nhất).
Nguyên nhân là các CVE 2025–2026 chưa có nhiều exploit công khai trong ExploitDB.
Trong khi đó ExploitDB hiện có 25.106 CVE duy nhất, phần lớn là CVE cũ.

Hệ quả:

- Stage CVE mô tả → ExploitDB description/SBERT sẽ rất mất cân bằng nếu chỉ
  dùng 55k mới nhất.
- Nếu muốn tái lập đầy đủ stage ExploitDB, nên dùng thêm một **exploit-linked
  subset** lịch sử (25.106 CVE có exploit) hoặc một chế độ chọn hybrid
  "newest + exploit coverage". Bản hiện tại chưa làm hybrid vì yêu cầu là
  chọn CVE mới nhất.

## 5. Sai lệch so với paper

| Điểm | Paper | Bản reproduction | Ghi chú |
|---|---:|---:|---|
| CVE | 114.560 | 55.000 | Theo yêu cầu lấy khoảng một nửa |
| CWE | 915 | 969 | Dùng CWE 4.20 hiện có |
| CAPEC | 1.024 | 615 | Dùng CAPEC 3.9 hiện có |
| Cặp CVE–CWE | 28.831 | 57.023 | NVD hiện có nhiều CWE hơn; sample mới nhất cũng khác paper |
| Cặp CWE–CAPEC | 46.575 | 1.212 | Paper có thể đếm theo mapping instance; bản này đếm cặp catalog duy nhất |
| Nguồn CVE | 1999–2023 | 2002–2026 | Latest mode vượt cutoff 2023 của paper |
| Human eval | 20 CVE của paper | 20 CVE mới nhất | Không CVE nào trong 20 CVE paper nằm trong 55k mới nhất; đây là deviation bắt buộc của latest mode |
| ExploitDB overlap | 1999–2023 | 27 dòng | Latest mode làm giảm mạnh độ phủ exploit |
| CAPEC tốt nhất | Có | Chưa | Thuộc bước 2 |

### CWE cũ / deprecated

142 dòng CVE–CWE dùng các CWE cũ không còn trong CWE 4.20, ví dụ:

- CWE-189: 29
- CWE-264: 25
- CWE-310: 22
- CWE-840: 19
- CWE-1035: 13
- CWE-320: 8
- CWE-275: 6
- CWE-265: 5
- CWE-19: 2
- CWE-255: 2

Các dòng này được giữ nguyên nhãn gốc và đánh dấu `cwe_in_catalog: false`.
Không tự động đổi sang CWE mới vì sẽ tạo nhãn nhân tạo. Hệ quả là các dòng này
không sinh được candidate CAPEC nếu catalog hiện tại không có quan hệ tương ứng.

## 6. File đầu ra

Tất cả nằm trong `data/processed/reproduction/` và đã được git-ignore:

```text
cves.jsonl                     55.000 CVE
cwe.json                       CWE catalog + quan hệ cha/con + CAPEC
capec.json                     CAPEC catalog + Execution Flow
cve_cwe.jsonl                  57.023 cặp CVE–CWE
cwe_capec.jsonl                1.212 cặp CWE–CAPEC
cve_capec_candidates.jsonl      candidate CAPEC cho từng cặp CVE–CWE
cve2capec_reference.jsonl       reference chỉ dùng cho evaluation
exploitdb.jsonl                 metadata ExploitDB, không có source code
splits.json                    train/validation/eval splits
stats.json                     toàn bộ số liệu và version catalog
```

## 7. Cách tái lập

Latest mode (bản đang dùng):

```bash
python scripts/download_reproduction_data.py --source all --start-year 2002 --end-year 2026
python scripts/build_reproduction_dataset.py --target-cves 55000 --selection-strategy newest
python scripts/audit_reproduction_dataset.py --dataset data/processed/reproduction
```

Paper-faithful mode (stratified 2002–2023):

```bash
python scripts/download_reproduction_data.py --source all --start-year 2002 --end-year 2023
python scripts/build_reproduction_dataset.py --target-cves 55000 --seed 42 --selection-strategy stratified
python scripts/audit_reproduction_dataset.py --dataset data/processed/reproduction
```

## 8. Việc tiếp theo

1. Chốt có dùng latest mode thuần hay hybrid cho stage ExploitDB.
2. Chọn CAPEC tốt nhất bằng TF-IDF/Word2Vec + cosine similarity.
3. Sinh execution flow từ CAPEC đã chọn.
4. Tạo dataset T5 hai stage và training script cho Kaggle T4 x2.
5. Đánh giá candidate/selection trên 100 CVE và so với CVE2CAPEC.
