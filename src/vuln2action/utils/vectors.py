"""Shared vector math for Word2Vec-based ranking."""

from __future__ import annotations

from typing import Any

import numpy as np


def mean_vector(model: Any, tokens: list[str]) -> np.ndarray | None:
    """Mean of known word vectors, L2-normalised; None when nothing is usable."""
    vectors = [model.wv[token] for token in tokens if token in model.wv]
    if not vectors:
        return None
    vector = np.mean(vectors, axis=0)
    norm = float(np.linalg.norm(vector))
    return vector / norm if norm else None
