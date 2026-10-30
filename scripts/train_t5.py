"""CPU-friendly fine-tuning of t5-small on CAPEC execution flows (P1.1).

The dataset is built by ``scripts/build_t5_dataset.py`` from MITRE CAPEC
``Execution_Flow`` phases; see ``docs/t5-training.md`` for provenance.

Downloads are explicit
--------------------
``--allow-download`` is required to fetch the base checkpoint. Without it the
script only uses a model already present in the local Hugging Face cache, so an
offline or CI machine fails with a clear message instead of silently downloading
hundreds of MB.

Determinism
-----------
``--seed`` seeds Python, NumPy and torch, and training uses a fixed
``torch.Generator`` for batch shuffling. CPU float ops are not bitwise identical
across machines/blas builds, so runs are *repeatable in procedure*, not promised
to be bit-identical everywhere.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.utils.filesystem import ensure_dir, read_json, write_json

DATASET = ("data", "processed", "t5_flows.json")
OUTPUT_DIR = ("models", "t5-capec-flows")
BASE_CHECKPOINT = "t5-small"


class TrainingError(RuntimeError):
    """Raised for unusable data or a missing optional dependency."""


def _safe_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def seed_everything(seed: int) -> None:
    """Seed every RNG we can reach; called before model construction."""
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:  # pragma: no cover - numpy ships with torch
        pass
    try:
        import torch

        torch.manual_seed(seed)
        torch.use_deterministic_algorithms(False)
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise TrainingError(
            "Fine-tuning needs torch and transformers. "
            'Install them with: python -m pip install -e ".[t5]"'
        ) from exc


def load_dataset(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not path.is_file():
        raise TrainingError(f"Dataset not found: {path}. Run: python scripts/build_t5_dataset.py")
    payload = read_json(path)
    train = payload.get("train") or []
    validation = payload.get("validation") or []
    if not train:
        raise TrainingError("Dataset has no training records")
    return train, validation


class FlowDataset:
    """Minimal tokenised dataset (no ``datasets`` dependency needed)."""

    def __init__(
        self,
        records: list[dict[str, Any]],
        tokenizer: Any,
        *,
        max_input_length: int,
        max_target_length: int,
    ) -> None:
        import torch

        self.encodings: list[dict[str, Any]] = []
        for record in records:
            model_input = tokenizer(
                record["input_text"],
                truncation=True,
                max_length=max_input_length,
                padding="max_length",
            )
            labels = tokenizer(
                record["target_flow"],
                truncation=True,
                max_length=max_target_length,
                padding="max_length",
            )
            label_ids = [
                token if token != tokenizer.pad_token_id else -100 for token in labels["input_ids"]
            ]
            self.encodings.append(
                {
                    "input_ids": torch.tensor(model_input["input_ids"]),
                    "attention_mask": torch.tensor(model_input["attention_mask"]),
                    "labels": torch.tensor(label_ids),
                }
            )

    def __len__(self) -> int:
        return len(self.encodings)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.encodings[index]


def _batches(indices: list[int], batch_size: int):
    for start in range(0, len(indices), batch_size):
        yield indices[start : start + batch_size]


def train(
    train_records: list[dict[str, Any]],
    validation_records: list[dict[str, Any]],
    *,
    base_checkpoint: str,
    output_dir: Path,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    max_input_length: int,
    max_target_length: int,
    seed: int,
    allow_download: bool,
    max_steps: int = 0,
    log_every: int = 10,
) -> dict[str, Any]:
    """Fine-tune and persist the checkpoint; returns a run summary."""
    seed_everything(seed)
    import torch
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    local_only = not allow_download
    try:
        tokenizer = AutoTokenizer.from_pretrained(base_checkpoint, local_files_only=local_only)
        model = AutoModelForSeq2SeqLM.from_pretrained(base_checkpoint, local_files_only=local_only)
    except (OSError, ValueError) as exc:
        raise TrainingError(
            f"Could not load {base_checkpoint!r}: {exc}. "
            "Re-run with --allow-download to fetch it explicitly."
        ) from exc

    train_dataset = FlowDataset(
        train_records,
        tokenizer,
        max_input_length=max_input_length,
        max_target_length=max_target_length,
    )
    val_dataset = (
        FlowDataset(
            validation_records,
            tokenizer,
            max_input_length=max_input_length,
            max_target_length=max_target_length,
        )
        if validation_records
        else None
    )
    if len(train_dataset) == 0:
        raise TrainingError("Training split is empty after tokenisation")

    device = torch.device("cpu")
    model.to(device)
    model.train()
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    generator = torch.Generator().manual_seed(seed)

    history: list[dict[str, Any]] = []
    step = 0
    stop = False
    for epoch in range(1, epochs + 1):
        order = torch.randperm(len(train_dataset), generator=generator).tolist()
        epoch_losses: list[float] = []
        for batch_indices in _batches(order, batch_size):
            batch = [train_dataset[index] for index in batch_indices]
            input_ids = torch.stack([item["input_ids"] for item in batch]).to(device)
            attention_mask = torch.stack([item["attention_mask"] for item in batch]).to(device)
            labels = torch.stack([item["labels"] for item in batch]).to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            step += 1
            epoch_losses.append(float(loss.item()))
            if log_every and step % log_every == 0:
                print(f"epoch={epoch} step={step} loss={loss.item():.4f}", flush=True)
            if max_steps and step >= max_steps:
                stop = True
                break
        epoch_loss = sum(epoch_losses) / len(epoch_losses) if epoch_losses else float("nan")
        history.append({"epoch": epoch, "train_loss": epoch_loss, "steps": step})
        print(f"epoch={epoch} mean_train_loss={epoch_loss:.4f}", flush=True)
        if stop:
            break

    val_loss = None
    if val_dataset is not None and len(val_dataset):
        model.eval()
        losses: list[float] = []
        with torch.no_grad():
            for batch_indices in _batches(list(range(len(val_dataset))), batch_size):
                batch = [val_dataset[index] for index in batch_indices]
                outputs = model(
                    input_ids=torch.stack([item["input_ids"] for item in batch]),
                    attention_mask=torch.stack([item["attention_mask"] for item in batch]),
                    labels=torch.stack([item["labels"] for item in batch]),
                )
                losses.append(float(outputs.loss.item()))
        val_loss = sum(losses) / len(losses) if losses else None

    ensure_dir(output_dir)
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    summary = {
        "base_checkpoint": base_checkpoint,
        "output_dir": str(output_dir),
        "seed": seed,
        "epochs_requested": epochs,
        "epochs_run": len(history),
        "batch_size": batch_size,
        "learning_rate": learning_rate,
        "max_input_length": max_input_length,
        "max_target_length": max_target_length,
        "max_steps": max_steps,
        "train_records": len(train_records),
        "validation_records": len(validation_records),
        "final_train_loss": history[-1]["train_loss"] if history else None,
        "validation_loss": val_loss,
        "history": history,
        "device": "cpu",
    }
    write_json(output_dir / "training_summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(description="Fine-tune t5-small on CAPEC flows (CPU).")
    parser.add_argument("--dataset", default=str(Path(*DATASET)), help="Dataset JSON.")
    parser.add_argument("--output", default=str(Path(*OUTPUT_DIR)), help="Checkpoint directory.")
    parser.add_argument("--base-checkpoint", default=BASE_CHECKPOINT, help="Base T5 checkpoint.")
    parser.add_argument("--epochs", type=int, default=3, help="Epochs (default: 3).")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size (default: 4).")
    parser.add_argument(
        "--learning-rate", type=float, default=5e-4, help="AdamW LR (default: 5e-4)."
    )
    parser.add_argument("--max-input-length", type=int, default=512)
    parser.add_argument("--max-target-length", type=int, default=512)
    parser.add_argument("--seed", type=int, default=13, help="Random seed (default: 13).")
    parser.add_argument("--max-steps", type=int, default=0, help="Stop after N steps (0 = all).")
    parser.add_argument("--log-every", type=int, default=10, help="Log every N steps.")
    parser.add_argument(
        "--allow-download",
        action="store_true",
        help="Explicitly permit fetching the base checkpoint from the Hub.",
    )
    parser.add_argument("--json-only", action="store_true", help="Print the summary as JSON.")
    args = parser.parse_args(argv)

    try:
        train_records, validation_records = load_dataset(_resolve(args.dataset))
        summary = train(
            train_records,
            validation_records,
            base_checkpoint=args.base_checkpoint,
            output_dir=_resolve(args.output),
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            max_input_length=args.max_input_length,
            max_target_length=args.max_target_length,
            seed=args.seed,
            allow_download=args.allow_download,
            max_steps=args.max_steps,
            log_every=args.log_every,
        )
    except TrainingError as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    if args.json_only:
        print(json.dumps(summary, indent=2))
    else:
        print(f"checkpoint saved to {summary['output_dir']}")
        print(
            f"train_loss={summary['final_train_loss']} "
            f"val_loss={summary['validation_loss']} epochs={summary['epochs_run']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
