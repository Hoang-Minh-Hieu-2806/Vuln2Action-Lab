# Hướng dẫn train T5 trên Kaggle T4 x2

Mục tiêu: fine-tune T5 stage 1 trên execution-flow dataset, dùng 2 GPU T4,
fp16, DDP, checkpoint/resume. Không có exploit code trong dataset.

## 1. Chuẩn bị dữ liệu

Trên máy local, build flow dataset (đã làm):

```bash
python scripts/build_flow_dataset.py \
  --dataset data/processed/reproduction \
  --predictions data/processed/reproduction/capec_selection/capec_predictions_word2vec_all.jsonl \
  --out data/processed/reproduction/flow_dataset
```

Các file cần upload lên Kaggle Dataset:

```text
flow_dataset/flow_train.jsonl
flow_dataset/flow_validation.jsonl
flow_dataset/flow_stats.json
```

Chỉ upload mô tả/metadata CVE/CAPEC; không upload exploit source code.
`flow_dataset.jsonl` không cần thiết nếu đã có train/validation.

## 2. Cài đặt trên Kaggle

Trong notebook:

```bash
pip install -e ".[train]"
```

Nếu repo chưa được clone:

```bash
git clone <repo-url>
cd Vuln2Action-Lab
pip install -e ".[train]"
```

Kaggle thường có sẵn `torch`; nếu phiên bản không khớp, để pip tự cài theo
`pyproject.toml`.

## 3. Chạy smoke test trước

```bash
python scripts/train_t5.py \
  --dataset /kaggle/input/<dataset-name>/flow_dataset \
  --output-dir /kaggle/working/smoke \
  --model-name t5-small \
  --target-field target_techniques \
  --max-input-length 256 \
  --max-target-length 256 \
  --max-steps 20 \
  --limit 200 \
  --no-auto-resume
```

Mục đích: kiểm tra tokenizer, dataloader, GPU, checkpoint. Không dùng kết quả
smoke để báo cáo BLEU.

## 4. Train stage 1 với T4 x2

```bash
python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
  --dataset /kaggle/input/<dataset-name>/flow_dataset \
  --output-dir /kaggle/working/t5_stage1 \
  --model-name t5-base \
  --target-field target_techniques \
  --max-input-length 256 \
  --max-target-length 256 \
  --per-device-batch-size 8 \
  --gradient-accumulation-steps 4 \
  --learning-rate 5e-5 \
  --num-train-epochs 50 \
  --save-steps 500 \
  --eval-steps 500 \
  --auto-resume
```

Cấu hình này tương đương:

- DDP 2 GPU;
- batch/GPU 8, gradient accumulation 4, effective batch 32;
- fp16;
- AdamW, lr `5e-5`;
- checkpoint mỗi 500 step, giữ 2 checkpoint gần nhất.

Nếu `t5-base` không fit hoặc epoch quá chậm:

1. giữ `t5-base`, giảm `--per-device-batch-size 4` và tăng
   `--gradient-accumulation-steps 8`;
2. hoặc dùng `t5-small` và ghi rõ đây là fallback, không phải cấu hình paper.

## 5. Resume sau khi Kaggle hết session

Output được lưu ở `/kaggle/working/t5_stage1`. Trước khi session kết thúc, copy
`checkpoint-*` sang Kaggle Dataset hoặc Google Drive.

Lần chạy sau:

```bash
python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
  --dataset /kaggle/input/<dataset-name>/flow_dataset \
  --output-dir /kaggle/working/t5_stage1 \
  --model-name t5-base \
  --target-field target_techniques \
  --max-input-length 256 \
  --max-target-length 256 \
  --per-device-batch-size 8 \
  --gradient-accumulation-steps 4 \
  --num-train-epochs 50 \
  --auto-resume
```

Script tự tìm `checkpoint-*` mới nhất theo số step. Không dùng nhiều tài khoản
Kaggle để né quota.

## 6. Đánh giá BLEU/ROUGE

```bash
python scripts/evaluate_t5.py \
  --checkpoint /kaggle/working/t5_stage1/final \
  --dataset /kaggle/input/<dataset-name>/flow_dataset \
  --split validation \
  --target-field target_techniques \
  --max-input-length 256 \
  --max-target-length 256 \
  --batch-size 8 \
  --num-beams 4
```

Kết quả ghi vào `outputs/t5_eval/metrics.json`:

- `bleu`
- `rouge1`
- `rouge2`
- `rougeL`

Paper báo cáo BLEU `0.7589`; reproduction chỉ được báo cáo số đo thực tế, không
được chép số paper.

## 7. Stage 2 v?i ExploitDB descriptions

Stage 2 dataset ?? c? t?i `data/processed/reproduction/flow_dataset_stage2/`.
Upload th?m c?c file:

```text
flow_dataset_stage2/flow_train.jsonl
flow_dataset_stage2/flow_validation.jsonl
flow_dataset_stage2/flow_stats.json
```

Ch?y stage 2:

```bash
python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
  --dataset /kaggle/input/<dataset-name>/flow_dataset_stage2 \
  --output-dir /kaggle/working/t5_stage2 \
  --model-name t5-base \
  --stage 2 \
  --target-field target_exploit_techniques \
  --max-input-length 256 \
  --max-target-length 128 \
  --per-device-batch-size 8 \
  --gradient-accumulation-steps 4 \
  --auto-resume
```

L?u ?: mapping technique -> ExploitDB description là semantic toàn cục, không
phải CVE-specific exploit code. Bản paper-faithful 55k có 6.474 dòng ExploitDB
khớp CVE được chọn, đủ cho pilot SBERT/exploit-code retrieval, nhưng vẫn chưa
phải coverage đầy đủ của paper 114.560 CVE.

## 8. Lưu ý an toàn

- Không upload exploit source code lên Kaggle.
- Chỉ dùng mô tả/metadata.
- Không chạy exploit tự động.
- Không trỏ pipeline ra ngoài localhost lab.
