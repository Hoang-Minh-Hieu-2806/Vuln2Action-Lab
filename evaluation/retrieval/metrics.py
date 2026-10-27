"""Retrieval metrics: precision@k, recall@k, F1@k, and MRR (no fabricated scores)."""

from __future__ import annotations


def precision_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    if k <= 0:
        return 0.0
    top = retrieved[:k]
    return sum(1 for r in top if r in relevant) / k


def recall_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 0.0
    top = set(retrieved[:k])
    return len(top & relevant) / len(relevant)


def f1_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    p = precision_at_k(retrieved, relevant, k)
    r = recall_at_k(retrieved, relevant, k)
    return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)


def mrr(rankings: list[list[str]], relevant_sets: list[set[str]]) -> float:
    """Mean reciprocal rank over multiple queries."""
    if not rankings:
        return 0.0
    total = 0.0
    for retrieved, relevant in zip(rankings, relevant_sets):
        for rank, doc in enumerate(retrieved, start=1):
            if doc in relevant:
                total += 1.0 / rank
                break
    return total / len(rankings)
