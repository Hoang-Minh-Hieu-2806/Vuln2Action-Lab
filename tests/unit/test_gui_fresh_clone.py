"""GUI startup is clear when the processed dataset is absent."""

import pytest

pytest.importorskip("flask")

from gui.app import create_app


def test_create_app_reports_missing_processed_dataset(tmp_path):
    before = sorted(p.name for p in tmp_path.iterdir())
    with pytest.raises(RuntimeError, match="GUI dataset is incomplete") as exc:
        create_app(dataset_dir=tmp_path)
    message = str(exc.value)
    assert "build_reproduction_dataset.py" in message
    assert "dataset_dir" in message
    assert "No data is downloaded" in message
    assert sorted(p.name for p in tmp_path.iterdir()) == before
