"""Prediction and evaluation helpers for best-CAPEC selection."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol

from vuln2action.domain import CapecPrediction, CapecSelectionMetrics
from vuln2action.mapping.corpus import SelectionDataset


class CapecSelector(Protocol):
    method: str

    def select(self, query: str, candidate_ids: Iterable[str]) -> tuple[str | None, float]: ...


def predict_capec(
    selector: CapecSelector,
    dataset: SelectionDataset,
    cve_ids: Sequence[str],
) -> list[CapecPrediction]:
    """Produce one top-1 CAPEC prediction per CVE."""
    predictions: list[CapecPrediction] = []
    for cve_id in cve_ids:
        cve = dataset.cves.get(cve_id)
        candidates = dataset.candidates.get(cve_id, ())
        references = dataset.references.get(cve_id, frozenset())
        selected: str | None = None
        score = 0.0
        if cve is not None and candidates:
            selected, score = selector.select(cve.description, candidates)
        correct = selected in references if selected is not None and references else None
        predictions.append(
            CapecPrediction(
                cve_id=cve_id,
                method=selector.method,
                selected_capec_id=selected,
                score=score,
                candidate_capec_ids=sorted(candidates),
                reference_capec_ids=sorted(references),
                correct=correct,
            )
        )
    return predictions


def selection_metrics(
    predictions: Sequence[CapecPrediction],
    split: str,
) -> CapecSelectionMetrics:
    with_candidates = sum(1 for prediction in predictions if prediction.candidate_capec_ids)
    with_reference = sum(1 for prediction in predictions if prediction.reference_capec_ids)
    evaluated = sum(
        1
        for prediction in predictions
        if prediction.candidate_capec_ids and prediction.reference_capec_ids
    )
    correct = sum(1 for prediction in predictions if prediction.correct is True)
    candidate_hits = sum(
        1
        for prediction in predictions
        if set(prediction.candidate_capec_ids) & set(prediction.reference_capec_ids)
    )
    total = len(predictions)
    return CapecSelectionMetrics(
        method=predictions[0].method if predictions else "",
        split=split,
        cves=total,
        with_candidates=with_candidates,
        with_reference=with_reference,
        evaluated=evaluated,
        correct=correct,
        accuracy=correct / total if total else 0.0,
        accuracy_answered=correct / evaluated if evaluated else 0.0,
        candidate_recall=candidate_hits / with_reference if with_reference else 0.0,
        mean_score=(
            sum(prediction.score for prediction in predictions if prediction.candidate_capec_ids)
            / with_candidates
            if with_candidates
            else 0.0
        ),
    )


def evaluate_selector(
    selector: CapecSelector,
    dataset: SelectionDataset,
    split: str,
    cve_ids: Sequence[str] | None = None,
    limit: int | None = None,
) -> tuple[list[CapecPrediction], CapecSelectionMetrics]:
    """Evaluate on a named split (or explicit ids) and return raw predictions."""
    if cve_ids is None:
        cve_ids = dataset.splits[split]
    if limit is not None:
        cve_ids = cve_ids[:limit]
    predictions = predict_capec(selector, dataset, cve_ids)
    return predictions, selection_metrics(predictions, split)
