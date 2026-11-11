"""Evaluate a fine-tuned T5 checkpoint with BLEU and ROUGE on flow targets."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
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


def _require_eval_deps() -> tuple[Any, ...]:
    try:
        import torch
        from datasets import load_dataset
        from rouge_score import rouge_scorer
        from sacrebleu import corpus_bleu, sentence_bleu
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
    except ImportError as exc:
        raise SystemExit(
            "T5 evaluation requires torch, transformers, datasets, sacrebleu, and "
            'rouge-score. Install them with `pip install -e ".[train]"`.'
        ) from exc
    return (
        torch,
        load_dataset,
        AutoModelForSeq2SeqLM,
        AutoTokenizer,
        corpus_bleu,
        sentence_bleu,
        rouge_scorer,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--dataset", default="data/processed/reproduction/flow_dataset")
    parser.add_argument("--split", choices=["validation", "train"], default="validation")
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
    parser.add_argument("--output-dir", default="outputs/t5_eval")
    parser.add_argument("--max-input-length", type=int, default=256)
    parser.add_argument("--max-target-length", type=int, default=256)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--num-beams", type=int, default=4)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--fp16", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args(argv)

    deps = _require_eval_deps()
    (
        torch,
        load_dataset,
        auto_model,
        auto_tokenizer,
        corpus_bleu,
        sentence_bleu,
        rouge_scorer,
    ) = deps

    dataset_dir = _resolve(args.dataset)
    split_file = dataset_dir / f"flow_{args.split}.jsonl"
    if not split_file.is_file():
        parser.error(f"missing flow split: {split_file}")
    raw = load_dataset("json", data_files={args.split: str(split_file)})[args.split]
    if args.limit is not None:
        raw = raw.select(range(min(args.limit, len(raw))))
    if args.target_field not in raw.column_names:
        parser.error(f"target field {args.target_field!r} is not in the dataset")

    checkpoint = _resolve(args.checkpoint)
    tokenizer = auto_tokenizer.from_pretrained(str(checkpoint))
    model = auto_model.from_pretrained(str(checkpoint))
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    model.eval()
    fp16 = bool(args.fp16 and torch.cuda.is_available())

    predictions: list[str] = []
    references: list[str] = []
    rows: list[dict[str, str]] = []
    for start in range(0, len(raw), args.batch_size):
        batch = raw[start : start + args.batch_size]
        inputs = tokenizer(
            batch["input"],
            max_length=args.max_input_length,
            truncation=True,
            padding=True,
            return_tensors="pt",
        )
        inputs = {key: value.to(device) for key, value in inputs.items()}
        autocast = (
            torch.autocast(device_type="cuda", dtype=torch.float16) if fp16 else nullcontext()
        )
        with torch.no_grad(), autocast:
            generated = model.generate(
                **inputs,
                max_length=args.max_target_length,
                num_beams=args.num_beams,
                early_stopping=True,
            )
        decoded = tokenizer.batch_decode(generated, skip_special_tokens=True)
        predictions.extend(decoded)
        references.extend(batch[args.target_field])
        rows.extend(
            {
                "cve_id": cve_id,
                "input": input_text,
                "reference": reference,
                "prediction": prediction,
            }
            for cve_id, input_text, reference, prediction in zip(
                batch["cve_id"],
                batch["input"],
                batch[args.target_field],
                decoded,
                strict=True,
            )
        )

    # The paper reports BLEU on a 0-1 scale and Algorithm 2 averages the
    # per-sample BLEU.  Keep corpus BLEU as a secondary, stricter metric.
    sentence_bleu_scores = [
        sentence_bleu(prediction, [reference]).score / 100.0
        for reference, prediction in zip(references, predictions, strict=True)
    ]
    bleu = sum(sentence_bleu_scores) / len(sentence_bleu_scores)
    bleu_corpus = corpus_bleu(predictions, [references]).score / 100.0

    scorer = rouge_scorer.RougeScorer(["rouge1", "rouge2", "rougeL"], use_stemmer=True)
    rouge_scores = [
        scorer.score(reference, prediction)
        for reference, prediction in zip(references, predictions, strict=True)
    ]
    rouge = {}
    for name in ("rouge1", "rouge2", "rougeL"):
        rouge[f"{name}_precision"] = (
            sum(score[name].precision for score in rouge_scores) / len(rouge_scores)
        )
        rouge[f"{name}_recall"] = (
            sum(score[name].recall for score in rouge_scores) / len(rouge_scores)
        )
        rouge[f"{name}_f1"] = (
            sum(score[name].fmeasure for score in rouge_scores) / len(rouge_scores)
        )
        rouge[name] = rouge[f"{name}_f1"]

    output_dir = _resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    metrics = {
        "checkpoint": str(checkpoint),
        "split": args.split,
        "target_field": args.target_field,
        "rows": len(rows),
        "bleu": bleu,
        "bleu_sentence": bleu,
        "bleu_corpus": bleu_corpus,
        "bleu_corpus_100": bleu_corpus * 100.0,
        "rouge1_precision": rouge["rouge1_precision"],
        "rouge1_recall": rouge["rouge1_recall"],
        "rouge1_f1": rouge["rouge1_f1"],
        "rouge2_precision": rouge["rouge2_precision"],
        "rouge2_recall": rouge["rouge2_recall"],
        "rouge2_f1": rouge["rouge2_f1"],
        "rougeL_precision": rouge["rougeL_precision"],
        "rougeL_recall": rouge["rougeL_recall"],
        "rougeL_f1": rouge["rougeL_f1"],
        "rouge1": rouge["rouge1"],
        "rouge2": rouge["rouge2"],
        "rougeL": rouge["rougeL"],
        "fp16": fp16,
        "num_beams": args.num_beams,
    }
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
