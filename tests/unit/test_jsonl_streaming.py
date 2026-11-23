"""JSONL reading is single-pass by default and explicit at random-access sites."""

import json

import pytest

from vuln2action.utils.filesystem import read_jsonl


def _write(tmp_path, content):
    path = tmp_path / "rows.jsonl"
    path.write_text(content, encoding="utf-8")
    return path


def test_empty_file_yields_nothing(tmp_path):
    assert list(read_jsonl(_write(tmp_path, ""))) == []


def test_one_row_and_multiple_rows(tmp_path):
    path = _write(tmp_path, '{"id": 1}\n{"id": 2}\n')
    assert list(read_jsonl(path)) == [{"id": 1}, {"id": 2}]


def test_blank_lines_are_skipped(tmp_path):
    path = _write(tmp_path, '{"id": 1}\n\n   \n{"id": 2}\n')
    assert [row["id"] for row in read_jsonl(path)] == [1, 2]


def test_unicode_is_preserved(tmp_path):
    path = _write(tmp_path, '{"text": "đồ án"}\n')
    assert list(read_jsonl(path)) == [{"text": "đồ án"}]


def test_malformed_json_raises(tmp_path):
    path = _write(tmp_path, "not-json\n")
    with pytest.raises(json.JSONDecodeError):
        list(read_jsonl(path))


def test_generator_is_single_pass(tmp_path):
    path = _write(tmp_path, '{"id": 1}\n{"id": 2}\n')
    rows = read_jsonl(path)
    assert next(rows) == {"id": 1}
    assert [row["id"] for row in rows] == [2]


def test_caller_can_materialise_for_random_access(tmp_path):
    path = _write(tmp_path, '{"id": 1}\n{"id": 2}\n')
    rows = list(read_jsonl(path))
    assert len(rows) == 2
    assert rows[0]["id"] == 1
    assert rows[1]["id"] == 2
