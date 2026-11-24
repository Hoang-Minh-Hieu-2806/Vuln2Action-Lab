# T5 Stage 1 — final run (Vietnamese)

Tài liệu này chốt hồ sơ thực nghiệm cho lần resume Stage 1 trên Kaggle sau khi kernel
`alexdannguyen/v2a-stage1-resume-checkpoint-3465` ở trạng thái `COMPLETE`. Mọi số liệu
dưới đây được đối chiếu với artifact local trong `data/external/resume_cp3465/`.

## Training setup

| Item | Value |
|---|---|
| Dataset | `dangthiet/vuln2action-p0-stage1` |
| Output dir trên Kaggle | `/kaggle/working/t5_stage1_resume_cp3465` |
| Model | `t5-base` |
| Stage | 1 |
| Target field | `target` |
| CAPEC in input | `false` (`--include_capec` không được bật) |
| Max input / target length | 512 / 512 |
| Batch | 8 mỗi GPU × 2 GPU × 4 gradient accumulation = 64 effective |
| Learning rate | `5e-5` |
| Warmup ratio / steps | 0.1 / 3465 (theo `training_config.json`) |
| Schedule | 50 epoch, dừng thực tế sau epoch 6 |
| Precision | FP32 (`fp16=false`, `--no-fp16`) |
| DDP | 2×T4, `torch.distributed.run --nproc_per_node=2` |
| Gradient checkpointing | `true` |
| Seed | 42 |
| Train rows | 44,331 |
| Validation rows | 11,089 |
| Train runtime trong log | 6121 giây |
| Final train loss trong log | 0.498 |

Lệnh train được ghi lại trong kernel log có chứa
`--resume-from-checkpoint /kaggle/input/datasets/alexdannguyen/v2a-stage1-cp3465-1123`
và `--stop-after-epoch 6`.

## Resume history

- Run trước đó trên account `ttalgies` dừng ở `global_step=3465`, epoch 5.
- Checkpoint `3465` được đóng gói thành dataset riêng
  `alexdannguyen/v2a-stage1-cp3465-1123` trên account `alexdannguyen`.
- Notebook resume dùng `--resume-from-checkpoint` trỏ tới dataset đó, không dùng
  `--auto-resume` vì checkpoint nằm ở `/kaggle/input`, không phải `output_dir`.
- Lần resume này tiến từ `global_step=3465` tới `global_step=4158`
  (693 step = 1 epoch), khớp `save_steps=693` và `stop_after_epoch=6`.
- `trainer_state.json` tại `checkpoint-4158` ghi:
  `epoch=6.0`, `global_step=4158`, `best_global_step=4158`,
  `best_metric=0.05401778593659401`,
  `best_model_checkpoint=/kaggle/working/t5_stage1_resume_cp3465/checkpoint-4158`.

## Validation protocol

- Script: `scripts/evaluate_t5.py`.
- Checkpoint được đánh giá: `/kaggle/working/t5_stage1_resume_cp3465/checkpoint-4158`.
- Split: `validation`.
- `target_field`: `target`.
- `include_capec`: `false`.
- `fp16`: `false`.
- `num_beams`: 4.
- `batch-size`: 4.
- Không dùng `--limit`; số dòng trong `metrics.json` và `predictions.jsonl` là 11,089.
- Kernel log ghi `EVAL_CKPT: .../checkpoint-4158` và in cùng một khối metrics với
  `metrics.json`.

## Kết quả quan sát được

| Metric | Giá trị trong artifact |
|---|---|
| BLEU (sentence) | 0.48018095742031747 ≈ 0.4802 |
| BLEU corpus | 0.5173661156672386 |
| ROUGE-1 F1 | 0.6465990716178283 |
| ROUGE-2 F1 | 0.5134467421402856 |
| ROUGE-L F1 | 0.5659283231713871 ≈ 0.5659 |
| Validation rows | 11089 |
| Eval loss tại epoch 6 | 0.05401778593659401 |

Đây là **observed validation result** trên split validation hiện có. Đây không phải
independent evaluation, không phải generalization evidence và không phải paper-comparable
result.

## Artifact inventory

Path tương đối tính từ gốc repo. Hash là SHA-256 tính từ file local.

| Path | Bytes | SHA-256 | Role | Provenance |
|---|---:|---|---|---|
| `data/external/resume_cp3465/t5_stage1_resume_cp3465/training_config.json` | 959 | `db9a81cd5f2c0f1d2f5870109524948354757ed957ccd3a574c6a39de1fce646` | Config thực tế của run resume | Tải từ Kaggle kernel output |
| `data/external/resume_cp3465/t5_stage1_resume_cp3465/checkpoint-4158/trainer_state.json` | 17354 | `a8b32cedc690b2bd35731780c79f47902d8277fafcc01a067eb5b61d0f5830d6` | Metadata checkpoint 4158 | Tải từ Kaggle kernel output |
| `data/external/resume_cp3465/t5_stage1_resume_cp3465_eval_full/metrics.json` | 800 | `0e234ad04434e01c67c954c544fec122a3f59fe2af36fc5e3ca6d244d08f287f` | Metrics đánh giá full validation | Tải từ Kaggle kernel output |
| `data/external/resume_cp3465/t5_stage1_resume_cp3465_eval_full/predictions.jsonl` | 42469548 | `c2987c041be4679cd37fb7c83a6a572aaad8f65c196fff520b58b0b30fca21bd` | 11,089 prediction rows | Tải từ Kaggle kernel output |
| `data/external/resume_cp3465/v2a-stage1-resume-checkpoint-3465.log` | 618782 | `3132381452635cf6b4cab83f01233a1fef966e9e8cd22cb89ba9aef4dd8b6929` | Kernel log chứa training + eval stdout | Tải từ Kaggle kernel output |

### Missing / không có local

| Item | Status | Lý do |
|---|---|---|
| `checkpoint-4158/model.safetensors` | Không có local | Không tải full model weights theo safety constraint; chỉ có metadata checkpoint |
| `checkpoint-4158/optimizer.pt`, scheduler/RNG | Không có local | Không tải full checkpoint theo safety constraint |
| `final/model.safetensors` | Không có local | Không tải full model weights; log chỉ xác nhận Kaggle đã lưu final model |
| Log stdout riêng cho evaluation | Không có file riêng | Training và evaluation nằm chung trong kernel log ở bảng trên; metrics/predictions là artifact eval |

Không tạo placeholder cho các file thiếu.

## Leakage limitation

Tài liệu hiện có ghi nhận **11,083/11,089** validation target trùng với train target
(`reports/definition-of-done.md`, `docs/defense/limitations-slide.md`). Vì vậy BLEU/ROUGE
ở trên bị ảnh hưởng bởi leakage và **không được dùng làm bằng chứng generalization**.
Không tự tính lại overlap trong đợt này; số liệu leakage được giữ nguyên từ hồ sơ hiện có.

## Claim boundaries

### Được phép

- Đã có artifact local cho config, trainer state, metrics, predictions và kernel log.
- Resume thành công từ `global_step=3465` tới `global_step=4158`, epoch 6.
- Trên validation split hiện có, với protocol đã ghi: BLEU ≈ 0.4802, ROUGE-L F1 ≈ 0.5659.
- Kết quả này là observed validation result, chịu limitation về leakage đã nêu.

### Không được phép

- Gọi đây là generalization evidence.
- Gọi đây là independent evaluation.
- Tuyên bố paper reproduction thành công hoặc so sánh trực tiếp với 0.7589/0.8594/0.7508
  như thể cùng protocol.
- Tự tính thêm metric ngoài evaluation protocol và artifact hiện có.
- Gán flow mẫu/reference của GUI cho T5 generated flow.
- Tuyên bố Docker validation hoặc human evaluation đã hoàn thành.
