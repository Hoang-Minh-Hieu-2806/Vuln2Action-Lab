"""Canonical mean-vector helper keeps ranking math stable."""

import numpy as np
import pytest

from vuln2action.utils.vectors import mean_vector


class _Model:
    def __init__(self, vectors):
        self.wv = vectors


def test_known_and_mixed_vocabulary():
    model = _Model({"a": np.array([3.0, 0.0]), "b": np.array([0.0, 4.0])})
    result = mean_vector(model, ["a", "b", "unknown"])
    np.testing.assert_allclose(result, np.array([0.6, 0.8]))


def test_empty_and_unknown_tokens_return_none():
    model = _Model({"a": np.array([1.0, 0.0])})
    assert mean_vector(model, []) is None
    assert mean_vector(model, ["unknown"]) is None


def test_zero_vector_returns_none():
    model = _Model({"a": np.array([1.0, 0.0]), "b": np.array([-1.0, 0.0])})
    assert mean_vector(model, ["a", "b"]) is None


def test_wrong_dimensions_raise():
    model = _Model({"a": np.array([1.0, 0.0]), "b": np.array([1.0, 2.0, 3.0])})
    with pytest.raises(ValueError):
        mean_vector(model, ["a", "b"])


def test_result_is_normalised():
    model = _Model({"a": np.array([9.0, 12.0])})
    result = mean_vector(model, ["a"])
    assert np.isclose(float(np.linalg.norm(result)), 1.0)
