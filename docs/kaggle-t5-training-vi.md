# H??ng d?n train T5 tr?n Kaggle T4 x2

M?c ti?u: fine-tune T5 stage 1 tr?n execution-flow dataset, d?ng 2 GPU T4,
fp16, DDP, checkpoint/resume. Kh?ng c? exploit source code trong dataset.

## 1. Dataset ?? upload

| Dataset | Kaggle |
|---|---|
| Stage 1 | `minhiw/vuln2action-flow-114560` |
| Stage 2 | `minhiw/vuln2action-stage2-114560` |

C? hai l? dataset private. Kaggle c? th? mount private dataset d??i:

```text
/kaggle/input/datasets/minhiw/vuln2action-flow-114560
/kaggle/input/datasets/minhiw/vuln2action-stage2-114560
```

Kh?ng hard-code path. Notebook smoke test t? d? `flow_train.jsonl` b?ng
`glob("/kaggle/input/**/flow_train.jsonl", recursive=True)`.

## 2. N?i dung upload

Stage 1:

```text
flow_train.jsonl
flow_validation.jsonl
flow_stats.json
```

Stage 2:

```text
flow_train.jsonl
flow_validation.jsonl
flow_stats.json
technique_exploit_map.jsonl
```

Kh?ng upload `flow_dataset.jsonl` full n?u ch? c?n train/validation. Kh?ng upload
exploit source code.

## 3. Notebook smoke test

File trong repo:

```text
notebooks/kaggle/kaggle_t5_smoke.ipynb
notebooks/kaggle/kernel-metadata.json
```

Notebook clone repo, c?i `.[train]`, d? dataset, ch?y dry-run, r?i ch?y
T5-small 20 steps v?i 500 rows.

K?t qu? smoke test ng?y 2026-11-10:

| H?ng m?c | K?t qu? |
|---|---|
| GPU | 2 x T4 |
| Torch | 2.11.0+cu130 |
| Model | t5-small |
| Rows | 500 train / 500 validation |
| Steps | 20 |
| Checkpoint | `checkpoint-10`, `checkpoint-20` |
| Eval loss | 10.02 ? 9.41 |
| Tr?ng th?i | COMPLETE |

Smoke test x?c nh?n DDP 2 GPU, fp16, ??c dataset, eval v? checkpoint ho?t ??ng.
L?n ch?y ??u l?i v? hard-code `/kaggle/input/vuln2action-flow-114560`; ?? s?a
b?ng t? d? `flow_train.jsonl`.

## 3b. K?t qu? benchmark 1 epoch

Notebook:

```text
notebooks/kaggle/stage1_benchmark/kaggle_t5_stage1_benchmark.ipynb
```

C?u h?nh:

| H?ng m?c | Gi? tr? |
|---|---:|
| Model | `t5-base` |
| Train / validation | 44.331 / 11.089 rows |
| Effective batch | 64 (8/GPU ? 2 GPU ? grad accum 4) |
| Steps / epoch | 693 |
| Max input / target | 256 / 256 |
| fp16 / gradient checkpointing | C? / C? |
| Tr?ng th?i | **COMPLETE** |

K?t qu?:

| Step | Eval loss |
|---:|---:|
| 500 | 0,5180 |
| 693 | **0,4455** |

??y m?i l? loss sau 1 epoch, ch?a ph?i BLEU/ROUGE cu?i c?ng. Kh?ng n?n so
tr?c ti?p v?i paper khi ch?a ch?y ?? epoch v? ch?a evaluate generation.

## 4. Train stage 1

Benchmark 1 epoch tr??c, kh?ng ch?y 50 epoch ngay:

```bash
python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
  --dataset /kaggle/input/datasets/minhiw/vuln2action-flow-114560 \
  --output-dir /kaggle/working/t5_stage1 \
  --model-name t5-base \
  --target-field target_techniques \
  --max-input-length 256 \
  --max-target-length 256 \
  --per-device-batch-size 8 \
  --gradient-accumulation-steps 4 \
  --num-train-epochs 1 \
  --save-steps 500 \
  --eval-steps 500 \
  --fp16 --gradient-checkpointing --auto-resume
```

N?u 1 epoch ?n v? th?i gian cho ph?p, t?ng l?n 50 epoch:

```bash
--num-train-epochs 50
```

Dataset stage 1 hi?n c? 44.331 train rows v? 11.089 validation rows. C?n ?o th?i
gian th?c t? tr?n T4 x2 tr??c khi cam k?t 50 epoch.

## 5. ??nh gi? stage 1

```bash
python scripts/evaluate_t5.py \
  --checkpoint /kaggle/working/t5_stage1/final \
  --dataset /kaggle/input/datasets/minhiw/vuln2action-flow-114560 \
  --target-field target_techniques \
  --num-beams 4
```

So s?nh T5-base v?i FLAN-T5-base tr?n c?ng validation split; ghi BLEU v?
ROUGE-1/2/L.

## 6. Resume

`--auto-resume` s? d?ng checkpoint m?i nh?t trong `--output-dir`. N?u ch?y tr?n
Kaggle notebook session m?i, copy checkpoint t? Kaggle Dataset/Drive v?
`/kaggle/working/t5_stage1` tr??c khi resume.

Checkpoint g?m:

```text
checkpoint-*/
final/
training_config.json
```

N?n upload checkpoint l?n Kaggle Dataset ho?c Google Drive sau m?i 500?1.000
steps. Kh?ng d?a v?o `/kaggle/working` v? th? m?c n?y m?t khi session k?t th?c.

## 7. Stage 2 v?i ExploitDB descriptions

```bash
python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
  --dataset /kaggle/input/datasets/minhiw/vuln2action-stage2-114560 \
  --output-dir /kaggle/working/t5_stage2 \
  --model-name t5-base \
  --stage 2 \
  --target-field target_exploit_techniques \
  --max-input-length 256 \
  --max-target-length 128 \
  --per-device-batch-size 8 \
  --gradient-accumulation-steps 4 \
  --fp16 --gradient-checkpointing --auto-resume
```

Mapping technique -> ExploitDB description l? semantic to?n c?c, kh?ng ph?i
CVE-specific exploit code. B?n 114.560 CVE c? 13.161 d?ng ExploitDB kh?p CVE
???c ch?n, ?? nguy?n li?u cho pilot SBERT/exploit-code retrieval, nh?ng ch?a
ch?y SBERT v? ch?a ph?i coverage ??y ??.

## 8. L?u ? an to?n

- Kh?ng upload exploit source code l?n Kaggle.
- Ch? d?ng m? t?/metadata.
- Kh?ng ch?y exploit t? ??ng.
- Kh?ng tr? pipeline ra ngo?i localhost lab.
