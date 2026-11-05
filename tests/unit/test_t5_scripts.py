from __future__ import annotations

from pathlib import Path

from scripts.train_t5 import _latest_checkpoint, _training_arguments


class _OldTrainingArguments:
    def __init__(self, output_dir: str, evaluation_strategy: str = "") -> None:
        self.output_dir = output_dir
        self.evaluation_strategy = evaluation_strategy


class _NewTrainingArguments:
    def __init__(self, output_dir: str, eval_strategy: str = "") -> None:
        self.output_dir = output_dir
        self.eval_strategy = eval_strategy


def test_training_arguments_supports_old_and_new_transformers_names():
    old = _training_arguments(_OldTrainingArguments, {"output_dir": "old"})
    new = _training_arguments(_NewTrainingArguments, {"output_dir": "new"})

    assert old.evaluation_strategy == "steps"
    assert new.eval_strategy == "steps"


def test_latest_checkpoint_uses_numeric_step_order(tmp_path: Path):
    (tmp_path / "checkpoint-100").mkdir()
    (tmp_path / "checkpoint-500").mkdir()
    (tmp_path / "checkpoint-50").mkdir()

    assert _latest_checkpoint(tmp_path) == str(tmp_path / "checkpoint-500")
    assert _latest_checkpoint(tmp_path / "missing") is None
