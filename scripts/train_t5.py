"""Fine-tune T5 on the stage-1 (or future stage-2) execution-flow dataset.

Kaggle T4 x2 example:

    python -m torch.distributed.run --nproc_per_node=2 scripts/train_t5.py \
        --dataset data/processed/reproduction/flow_dataset \
        --output-dir /kaggle/working/t5_stage1 \
        --model-name t5-base --target-field target_techniques \
        --max-target-length 256 --auto-resume

The script uses Hugging Face Trainer, so DDP, fp16, gradient accumulation, and
checkpoint resume are handled by the trainer. It does not execute exploit code.
"""

from __future__ import annotations

import argparse
import inspect
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _latest_checkpoint(output_dir: Path) -> str | None:
    checkpoints = sorted(
        output_dir.glob("checkpoint-*"),
        key=lambda path: int(path.name.rsplit("-", 1)[-1]),
    )
    return str(checkpoints[-1]) if checkpoints else None


def _require_training_deps() -> tuple[Any, ...]:
    try:
        import torch
        from datasets import load_dataset
        from transformers import (
            AutoModelForSeq2SeqLM,
            AutoTokenizer,
            DataCollatorForSeq2Seq,
            Seq2SeqTrainer,
            Seq2SeqTrainingArguments,
            TrainerCallback,
        )
    except ImportError as exc:
        raise SystemExit(
            "T5 training requires torch, transformers, datasets, and accelerate. "
            'Install them with `pip install -e ".[train]"`.'
        ) from exc
    return (
        torch,
        load_dataset,
        AutoModelForSeq2SeqLM,
        AutoTokenizer,
        DataCollatorForSeq2Seq,
        Seq2SeqTrainer,
        Seq2SeqTrainingArguments,
        TrainerCallback,
    )


def _training_arguments(training_arguments_cls: Any, kwargs: dict[str, Any]) -> Any:
    """Support both transformers' old and new evaluation-strategy argument."""
    parameters = inspect.signature(training_arguments_cls.__init__).parameters
    strategy_key = "eval_strategy" if "eval_strategy" in parameters else "evaluation_strategy"
    return training_arguments_cls(**{**kwargs, strategy_key: "steps"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/processed/reproduction/flow_dataset")
    parser.add_argument("--output-dir", default="outputs/t5_stage1")
    parser.add_argument("--model-name", default="t5-base")
    parser.add_argument("--stage", type=int, choices=[1, 2], default=1)
    parser.add_argument(
        "--target-field",
        choices=[
            "target",
            "target_steps",
            "target_techniques",
            "target_exploit",
            "target_exploit_techniques",
        ],
        default="target_techniques",
    )
    parser.add_argument("--source-prefix", default="")
    parser.add_argument(
        "--include-capec",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Condition the input on the selected CAPEC name/id. This is an "
            "operational variant, not the paper's CVE-only input."
        ),
    )
    parser.add_argument("--max-input-length", type=int, default=256)
    parser.add_argument("--max-target-length", type=int, default=256)
    parser.add_argument("--per-device-batch-size", type=int, default=8)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=5e-5)
    parser.add_argument(
        "--warmup-ratio",
        type=float,
        default=0.1,
        help="Fraction of steps used for linear warmup (default: 0.1).",
    )
    parser.add_argument(
        "--warmup-steps",
        type=int,
        default=-1,
        help="Override warmup steps; -1 computes it from --warmup-ratio.",
    )
    parser.add_argument("--num-train-epochs", type=float, default=50.0)
    parser.add_argument(
        "--stop-after-epoch",
        type=float,
        default=None,
        help=(
            "Stop training after this epoch while keeping the LR schedule length "
            "defined by --num-train-epochs. Useful for evaluating an early epoch "
            "of a longer paper-style schedule."
        ),
    )
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument("--save-steps", type=int, default=500)
    parser.add_argument("--eval-steps", type=int, default=500)
    parser.add_argument("--logging-steps", type=int, default=50)
    parser.add_argument("--save-total-limit", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--limit", type=int, default=None, help="Smoke-test cap on rows.")
    parser.add_argument("--fp16", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--gradient-checkpointing",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--auto-resume", action="store_true")
    parser.add_argument("--resume-from-checkpoint", default="")
    parser.add_argument(
        "--load-best-model-at-end",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Reload the checkpoint with the lowest eval loss. Paper-style runs "
            "should keep the final epoch, so this defaults to false."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    deps = _require_training_deps()
    (
        torch,
        load_dataset,
        auto_model,
        auto_tokenizer,
        data_collator_cls,
        trainer_cls,
        training_arguments_cls,
        trainer_callback_cls,
    ) = deps

    dataset_dir = _resolve(args.dataset)
    train_file = dataset_dir / "flow_train.jsonl"
    validation_file = dataset_dir / "flow_validation.jsonl"
    if not train_file.is_file() or not validation_file.is_file():
        parser.error(
            f"missing {train_file.name}/{validation_file.name} under {dataset_dir}; "
            "run scripts/build_flow_dataset.py first"
        )

    raw = load_dataset(
        "json",
        data_files={"train": str(train_file), "validation": str(validation_file)},
    )
    if args.limit is not None:
        raw["train"] = raw["train"].select(range(min(args.limit, len(raw["train"]))))
        raw["validation"] = raw["validation"].select(range(min(args.limit, len(raw["validation"]))))
    if args.target_field not in raw["train"].column_names:
        parser.error(
            f"target field {args.target_field!r} is not in the flow dataset; "
            "stage 2 needs an enriched target field"
        )

    tokenizer = auto_tokenizer.from_pretrained(args.model_name)
    model = auto_model.from_pretrained(args.model_name)
    model.config.use_cache = False

    def preprocess(batch: dict[str, list[Any]]) -> dict[str, Any]:
        if args.include_capec:
            inputs = [
                f"{args.source_prefix}CAPEC {capec_id}: {capec_name}\nCVE: {text}"
                for text, capec_id, capec_name in zip(
                    batch["input"], batch["capec_id"], batch["capec_name"], strict=True
                )
            ]
        else:
            inputs = [
                f"{args.source_prefix}{text}" if args.source_prefix else text
                for text in batch["input"]
            ]
        model_inputs = tokenizer(
            inputs,
            max_length=args.max_input_length,
            truncation=True,
        )
        labels = tokenizer(
            text_target=batch[args.target_field],
            max_length=args.max_target_length,
            truncation=True,
        )
        model_inputs["labels"] = labels["input_ids"]
        return model_inputs

    tokenized = raw.map(
        preprocess,
        batched=True,
        remove_columns=raw["train"].column_names,
        desc="tokenizing execution flows",
    )

    if args.dry_run:
        print(f"stage={args.stage} train={len(tokenized['train'])}")
        print(f"validation={len(tokenized['validation'])}")
        for index in range(min(2, len(tokenized["train"]))):
            row = tokenized["train"][index]
            print(
                f"row={index} input_tokens={len(row['input_ids'])} "
                f"target_tokens={len(row['labels'])}"
            )
        return 0

    world_size = int(os.environ.get("WORLD_SIZE", "1") or "1")
    steps_per_epoch = math.ceil(
        len(tokenized["train"])
        / max(1, args.per_device_batch_size * world_size * args.gradient_accumulation_steps)
    )
    if args.max_steps > 0:
        total_steps = args.max_steps
    else:
        total_steps = max(1, math.ceil(steps_per_epoch * args.num_train_epochs))
    warmup_steps = (
        args.warmup_steps
        if args.warmup_steps >= 0
        else int(total_steps * args.warmup_ratio)
    )

    output_dir = _resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    training_kwargs: dict[str, Any] = {
        "output_dir": str(output_dir),
        "per_device_train_batch_size": args.per_device_batch_size,
        "per_device_eval_batch_size": args.per_device_batch_size,
        "gradient_accumulation_steps": args.gradient_accumulation_steps,
        "learning_rate": args.learning_rate,
        "num_train_epochs": args.num_train_epochs,
        "max_steps": args.max_steps,
        "save_steps": args.save_steps,
        "eval_steps": args.eval_steps,
        "logging_steps": args.logging_steps,
        "save_total_limit": args.save_total_limit,
        "save_strategy": "steps",
        "load_best_model_at_end": args.load_best_model_at_end,
        "metric_for_best_model": "eval_loss",
        "greater_is_better": False,
        "predict_with_generate": False,
        "fp16": bool(args.fp16 and torch.cuda.is_available()),
        "gradient_checkpointing": args.gradient_checkpointing,
        "optim": "adamw_torch",
        "report_to": "none",
        "seed": args.seed,
        "data_seed": args.seed,
        "dataloader_num_workers": 2,
        "remove_unused_columns": False,
    }
    training_params = inspect.signature(training_arguments_cls.__init__).parameters
    if "warmup_steps" in training_params:
        training_kwargs["warmup_steps"] = warmup_steps
    elif "warmup_ratio" in training_params:
        training_kwargs["warmup_ratio"] = args.warmup_ratio
    training_args = _training_arguments(training_arguments_cls, training_kwargs)

    callbacks = None
    if args.stop_after_epoch is not None:
        stop_after_epoch = args.stop_after_epoch

        class _StopAfterEpoch(trainer_callback_cls):
            def on_epoch_end(self, args, state, control, **kwargs):
                if state.epoch is not None and state.epoch >= stop_after_epoch:
                    control.should_training_stop = True

        callbacks = [_StopAfterEpoch()]

    trainer = trainer_cls(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        data_collator=data_collator_cls(tokenizer, model=model, padding="longest"),
        callbacks=callbacks,
    )

    if torch.cuda.is_available():
        print(
            f"CUDA devices={torch.cuda.device_count()} fp16={training_args.fp16} stage={args.stage}"
        )
    else:
        print("CUDA is unavailable; running on CPU (fp16 disabled)")

    config = {
        **vars(args),
        "train_rows": len(tokenized["train"]),
        "validation_rows": len(tokenized["validation"]),
        "total_steps": total_steps,
        "warmup_steps": warmup_steps,
    }
    (output_dir / "training_config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    resume: str | None = None
    if args.resume_from_checkpoint:
        resume = str(_resolve(args.resume_from_checkpoint))
    elif args.auto_resume:
        resume = _latest_checkpoint(output_dir)
        if resume:
            print(f"auto-resuming from {resume}")
        else:
            print("auto-resume requested but no checkpoint found; starting fresh")
    trainer.train(resume_from_checkpoint=resume)

    if trainer.is_world_process_zero():
        trainer.save_model(str(output_dir / "final"))
        tokenizer.save_pretrained(str(output_dir / "final"))
        print(f"saved final model to {output_dir / 'final'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
