"""Generation metrics scaffold (BLEU/ROUGE/semantic/human eval).

Phase 1 ships only a dependency-free token-F1 helper; BLEU/ROUGE wiring is
TODO(Phase 7) so we add no heavy deps now. Never fabricate scores.
"""
from __future__ import annotations

import re


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def unigram_f1(candidate: str, reference: str) -> float:
    """Tiny overlap metric as a stand-in until BLEU/ROUGE are wired."""
    c, r = _tokens(candidate), _tokens(reference)
    if not c or not r:
        return 0.0
    from collections import Counter

    cc, rc = Counter(c), Counter(r)
    overlap = sum((cc & rc).values())
    p = overlap / len(c)
    rec = overlap / len(r)
    return 0.0 if (p + rec) == 0 else 2 * p * rec / (p + rec)


# TODO(Phase 7): bleu_score(candidate, reference), rouge_scores(...),
# semantic_similarity(...), plus a human-eval rubric template.
