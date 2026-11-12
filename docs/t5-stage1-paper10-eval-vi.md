# T5 stage 1 - đánh giá checkpoint epoch 10 và pilot full-flow

## 1. Kết quả 10 epoch

Notebook:

```text
minhiw/vuln2action-t5-stage1-paper-eval10
```

Checkpoint được đánh giá:

```text
checkpoint-6930 (epoch 10)
```

| Metric | Giá trị |
|---|---:|
| Rows | 11.089 |
| BLEU trung bình từng câu (0-1) | **0,1640** |
| Corpus BLEU (0-1) | 0,2799 |
| ROUGE-1 Precision / Recall / F1 | 0,3899 / 0,5064 / 0,3553 |
| ROUGE-2 Precision / Recall / F1 | 0,2365 / 0,1845 / 0,1982 |
| ROUGE-L Precision / Recall / F1 | 0,3160 / 0,4235 / 0,2831 |

So với paper:

| Metric | Paper T5 | Hiện tại |
|---|---:|---:|
| BLEU | 0,7589 | 0,1640 |
| ROUGE-1 F1 | 0,8126 | 0,3553 |
| ROUGE-L F1 | 0,7950 | 0,2831 |

## 2. So với checkpoint 1 epoch

| Metric | 1 epoch | 10 epoch |
|---|---:|---:|
| BLEU trung bình từng câu | 0,2792 | 0,1640 |
| Corpus BLEU | 0,4071 | 0,2799 |
| ROUGE-1 F1 | 0,4493 | 0,3553 |
| ROUGE-L F1 | 0,3950 | 0,2831 |
| Exact match | 847 / 11.089 (7,64%) | 209 / 11.089 (1,88%) |

Train thêm epoch làm kết quả xấu đi. Vì vậy vấn đề không phải chỉ là
"chưa đủ 50 epoch".

## 3. Model collapse ở 10 epoch

- 11.089 rows nhưng chỉ có **25 prediction khác nhau**.
- Top 8 prediction chiếm **94,34%**.
- Prediction phổ biến nhất chiếm **4.879 / 11.089 = 44,0%**.
- 14,25% reference là flow rỗng `Explore: Experiment: Exploit:`, nhưng model
  không sinh flow rỗng lần nào.
- Nhiều CVE khác nhau nhận cùng một flow spidering / web application.

## 4. Pilot full execution flow

Pilot dùng `target` (step description + technique) thay vì
`target_techniques`, train 1 epoch, evaluate trên 1.000 validation rows đầu.

```text
minhiw/vuln2action-t5-stage1-target-pilot
checkpoint: final (epoch 1)
```

| Metric | 1 epoch, `target` | 1 epoch, `target_techniques` (cùng 1.000 rows) | 10 epoch, `target_techniques` (cùng 1.000 rows) |
|---|---:|---:|---:|
| BLEU | **0,0665** | 0,3982 | 0,1947 |
| Corpus BLEU | 0,1001 | 0,4898 | 0,3184 |
| ROUGE-1 F1 | 0,1954 | 0,5787 | 0,4028 |
| ROUGE-2 F1 | 0,0760 | 0,4732 | 0,2406 |
| ROUGE-L F1 | 0,1456 | 0,5231 | 0,3243 |
| Exact match | 0,00% | 13,40% | 3,60% |

Pilot không sửa được lỗi. Model sinh 733 output khác nhau nhưng nội dung bị
lặp cụm, ví dụ:

```text
Explore: [Survey the application for stored user-controllable inputs]
Exploit: [Survey the application for stored user-controllable inputs]
Exploit: [Survey the application for stored user-controllable inputs]
Exploit: [Survey the application for stored user-controllable inputs]
...
```

Các số liệu cấu trúc:

- 1.000/1.000 output có `Explore:`.
- 765/1.000 có `Experiment:`.
- 613/1.000 có `Exploit:`.
- Chỉ 406/1.000 có đủ cả ba phase.
- Chỉ 46/1.000 kết thúc bằng dấu chấm.
- Độ dài trung bình: reference 311,8 từ, prediction 310,6 từ. Model không bị
  ngắn output; nó sinh đủ dài nhưng sai nội dung và lặp.

Eval loss của pilot là **2,876**, so với **0,258** của 1 epoch
`target_techniques`. Full target khó hơn rất nhiều.

Lưu ý: loss train hiển thị 23-32 trong log là do gradient accumulation
(`gradient_accumulation_steps=8`), không phải loss thật tăng 8 lần. Không nên
đọc các con số đó như bằng chứng model diverged.

## 5. Nguyên nhân

### 5.1. `target_techniques` có nhiều nhãn rỗng

- **6.277 / 44.331** train rows có target rỗng (14,2%).
- Chỉ có **139 target khác nhau** trong train, **125** trong validation.
- Top 5 target chiếm 42,1%; top 10 chiếm 61,4%; top 20 chiếm 81,3%.

Với phân phối này, model dễ học flow phổ biến thay vì ánh xạ CVE -> flow.
Đây là lỗi chất lượng dữ liệu, không chỉ là lỗi chọn epoch.

### 5.2. Full target quá dài so với ngân sách 512 token

- `target`: mean 286,6 từ, P90 521 từ, 12,3% rows dài hơn 512 từ.
- `target_steps`: mean 143,6 từ, P90 213 từ.
- `target_techniques`: mean 143,3 từ, P90 285 từ.

Với `max_target_length=512`, một phần đáng kể full target bị cắt. Pilot 1 epoch
chưa đủ để học cấu trúc full flow, nên model rơi vào vòng lặp cụm từ.

### 5.3. 10 epoch không phải là 10 epoch đầu của 50 epoch

Learning-rate schedule được tính theo tổng số epoch. Chạy `num_train_epochs=10`
làm LR giảm về 0 ở epoch 10; chạy 50 epoch thì ở epoch 10 LR vẫn còn khoảng
4e-5. Vì vậy kết quả 10 epoch không chứng minh trực tiếp rằng 50 epoch cũng sẽ
tệ như vậy. Tuy nhiên, nó đủ để thấy cấu hình hiện tại chưa ổn.

### 5.4. Độ phủ dữ liệu thấp hơn paper

Theo báo cáo dataset hiện tại:

- 55.420 flow rows trên 114.560 CVE.
- 176 CAPEC có execution flow.
- 44.753 CVE không có selected CAPEC.
- 14.267 selected CAPEC không có execution flow.
- Paper dùng khoảng 1.024 CAPEC.

Đây là khoảng cách lớn về số lượng nhãn và độ đa dạng flow. Với 139 nhãn khác
nhau, BLEU 0,7589 khó đạt được, đặc biệt khi input chỉ là CVE description.

### 5.5. Overlap validation

11.083/11.089 validation target đã xuất hiện nguyên văn trong train. Metric hiện
tại đo mức độ khớp template/overlap nhiều hơn là khả năng tổng quát hóa. Kể cả
với overlap này, BLEU vẫn chỉ 0,164, nên chất lượng model thực sự thấp.

## 6. Kết luận

- Eval full đã chạy xong; metric paper-style đầy đủ.
- Kết quả 10 epoch rất thấp: BLEU 0,1640 so với paper 0,7589.
- 10 epoch còn tệ hơn 1 epoch; model bị collapse về một vài flow phổ biến.
- Pilot full target 1 epoch cũng thất bại: BLEU 0,0665, output lặp cụm.
- Không nên chạy 50 epoch một cách mù quáng với cấu hình hiện tại.

## 7. Hướng tiếp theo

Thứ tự hợp lý:

1. Thử `target_steps` (ngắn hơn, không rỗng) với warmup 0,1 và 5-10 epoch.
   Đây là biến thể sát paper hơn `target_techniques` nhưng vẫn vừa ngân sách
   512 token.
2. Nếu `target_steps` tốt hơn, chạy 10 epoch rồi đánh giá full validation.
3. Nếu vẫn thấp, phải mở rộng độ phủ CAPEC/execution flow về gần 1.024 CAPEC
   như paper; tăng epoch không giải quyết được thiếu đa dạng nhãn.
4. Chỉ chạy 50 epoch khi target và dataset đã ổn định; ghi rõ nếu phải dùng
   `target_steps` thay cho full flow.

Các thay đổi code đã có:

- `scripts/train_t5.py` mặc định không reload checkpoint có eval loss thấp nhất;
  giữ epoch cuối giống paper.
- Có thể chọn `--target-field target_steps` hoặc `target` mà không cần sửa code.

## 8. Pilot CAPEC-conditioned (biến thể operational)

Để kiểm tra nút thắt nằm ở T5 hay ở bước chọn CAPEC, đã chạy một pilot đưa
CAPEC đã chọn vào input:

```text
CAPEC CAPEC-540: Overread Buffers
CVE: <CVE description>
```

Cấu hình: `target_steps`, 1 epoch, batch 8/GPU, gradient accumulation 4,
warmup 0,1, `max_target_length=384`, evaluate 1.000 validation rows.

Notebook:

```text
minhiw/vuln2action-t5-stage1-capec-conditioned
```

| Metric | CVE-only, `target_steps` epoch 1 | CAPEC-conditioned, epoch 1 | Paper |
|---|---:|---:|---:|
| BLEU | 0,2567 | **0,8594** | 0,7589 |
| Corpus BLEU | 0,2944 | **0,8858** | — |
| ROUGE-1 F1 | 0,4887 | **0,9058** | 0,8126 |
| ROUGE-2 F1 | 0,2748 | **0,8645** | — |
| ROUGE-L F1 | 0,3686 | **0,8840** | 0,7950 |
| Exact match | 100/1.000 (10%) | **801/1.000 (80,1%)** | — |

Các quan sát:

- 1.000/1.000 prediction có đủ `Explore:`, `Experiment:`, `Exploit:`.
- 64 prediction khác nhau; 56 reference khác nhau.
- Top 1 prediction chiếm 14,1%; top 8 chiếm 70,6%.
- Các CAPEC phổ biến đạt exact 100% (ví dụ CAPEC-63, CAPEC-110,
  CAPEC-126, CAPEC-14, CAPEC-592).
- 199 lỗi chủ yếu rơi vào CAPEC hiếm, chỉ có 1-2 validation row.

**Cảnh báo quan trọng:** đây không phải input CVE-only của paper. Target flow
được sinh từ chính CAPEC đã chọn, nên khi đưa CAPEC vào input, model chỉ cần
render flow cho CAPEC đó; metric này đo chất lượng "CAPEC -> flow", không đo
trực tiếp "CVE -> flow". Vì vậy không được so trực tiếp 0,8594 với 0,7589 của
paper như cùng một thiết lập. Đây là biến thể operational có thể dùng khi
pipeline đã có CAPEC selection (97,91% accuracy trên CVE có candidate), nhưng
chất lượng end-to-end vẫn phụ thuộc vào bước chọn CAPEC và coverage CVE.

## 9. LR 2e-5 và dataset mở rộng

### 9.1. LR 2e-5, 3 epoch

Đã chạy lại CVE-only `target_steps` với LR `2e-5`, warmup `0,06`, 3 epoch và
evaluate từng checkpoint trên cùng 1.000 validation rows. Kết quả:

| Checkpoint | BLEU | Corpus BLEU | ROUGE-1 F1 | ROUGE-2 F1 | ROUGE-L F1 | Exact |
|---|---:|---:|---:|---:|---:|---:|
| 693 (epoch 1) | 0,1538 | 0,2299 | 0,3911 | 0,1898 | 0,2932 | 0/1.000 |
| 1386 (epoch 2) | 0,1538 | 0,2299 | 0,3911 | 0,1898 | 0,2932 | 0/1.000 |
| 2079 (epoch 3) | 0,1538 | 0,2299 | 0,3911 | 0,1898 | 0,2932 | 0/1.000 |

Ba checkpoint cho ra `predictions.jsonl` giống nhau từng byte và eval loss
trùng khớp `2,360677`. Kiểm tra thêm file `model.safetensors` cho thấy
`checkpoint-693`, `checkpoint-1386`, `checkpoint-2079` và `final/` đều có
cùng SHA-256:

```text
7F5754879CBADA36215DAD2B4BBC70ABE413B51518BD0488ED6B9E2481C4E694
```

Vì vậy đây chỉ là **một** kết quả model, không phải ba điểm dữ liệu độc lập.
Cần kiểm tra lại cơ chế save/checkpoint nếu muốn dùng LR này; không dùng nó
cho stage 2.

Kết luận: LR `2e-5` **không cải thiện** CVE-only. BLEU 0,1538 thấp hơn mức
0,2567 của LR `5e-5` epoch 1. Không dùng LR này cho stage 2.

### 9.2. Dataset mở rộng 80.477 rows

Để tăng coverage thay vì tăng epoch, đã dùng dataset mở rộng:

```text
data/processed/reproduction/flow_dataset_expanded/
```

Thống kê: 80.477 rows, 64.388 train / 16.089 validation, 187 CAPEC có flow.
Dataset và notebook được đưa sang tài khoản Kaggle thứ hai để tránh phụ thuộc
quota của `minhiw`:

```text
hoangdang1711/vuln2action-flow-expanded-80k
hoangdang1711/vuln2action-eval-common-1000
hoangdang1711/vuln2action-t5-expanded-1ep
```

Thiết lập:

- CVE-only, `target_steps`, không đưa CAPEC vào input.
- `t5-base`, LR `5e-5`, warmup `0,1`, 1 epoch.
- batch 8/GPU, gradient accumulation 4, 2x T4, fp16.
- Evaluate trên đúng 1.000 validation rows đầu của baseline cũ, lưu thành
  `vuln2action-eval-common-1000`, để so sánh trực tiếp với BLEU 0,2567.
- Chỉ upload CVE description, CAPEC flow và metadata; không có exploit source.

Kết quả 1 epoch:

| Metric | Baseline 1 epoch | Expanded 1 epoch | Paper |
|---|---:|---:|---:|
| BLEU | **0,2567** | 0,1722 | 0,7589 |
| Corpus BLEU | 0,2944 | 0,2299 | — |
| ROUGE-1 F1 | **0,4887** | 0,4136 | 0,8126 |
| ROUGE-2 F1 | **0,2748** | 0,1993 | — |
| ROUGE-L F1 | **0,3686** | 0,3124 | 0,7950 |
| Exact match | **100/1.000** | 0/1.000 | — |

Các quan sát:

- Expanded model sinh 218 prediction khác nhau; top 1 chiếm 15,9%, top 8
  chiếm 57,8%.
- 1.000/1.000 có `Explore:`, 1.000/1.000 có `Experiment:`, 982/1.000 có
  `Exploit:`.
- Độ dài trung bình: reference 148,8 từ, prediction 115,1 từ. Model sinh
  ngắn hơn reference; baseline sinh 186,1 từ.
- 1.000/1.000 target của common set vẫn xuất hiện trong train của cả baseline
  và expanded, nên chênh lệch không phải do thay đổi leakage.
- Eval loss: baseline epoch 1 khoảng 0,996; expanded 1 epoch 1,889.

**Chưa thể kết luận dataset mở rộng thất bại**, vì baseline epoch 1 được lấy
từ lịch 5 epoch: tại bước 693, LR vẫn khoảng 4e-5. Run expanded ở trên dùng
`num_train_epochs=1`, nên LR giảm về 0 ngay trong epoch đầu; model có thể chỉ
đang undertrained.

### 9.3. Chạy lại với lịch 5 epoch, dừng sau epoch 1

Để so sánh công bằng, đã thêm `--stop-after-epoch` vào `scripts/train_t5.py`:
lịch LR vẫn được tính theo `--num-train-epochs=5`, nhưng dừng sau epoch 1.
Notebook:

```text
hoangdang1711/vuln2action-t5-expanded-5ep-sched
```

Thiết lập giống baseline epoch 1:

- `num_train_epochs=5`, `stop_after_epoch=1`
- LR `5e-5`, warmup `0,1`
- 1.007 steps/epoch, evaluate trên cùng common 1.000 rows

Kernel đang chạy; kết quả sẽ được cập nhật sau khi monitor tải xong.
