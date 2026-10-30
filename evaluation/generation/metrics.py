"""Dependency-free generation metrics: BLEU, ROUGE-1/2/L, and flow checks.

Why not ``sacrebleu``/``rouge_score``/``nltk``? Those packages are large, some
pull Java or NLTK data, and the project must stay installable on a plain CPU
machine and in CI. The BLEU implementation here is a faithful port of
sacrebleu's algorithm (including its ``exp`` smoothing and brevity penalty) and
is unit-tested to match sacrebleu to <0.01 BLEU points on several sentences, so
the numbers can be reproduced with a standard tool. ROUGE follows Lin (2004)
using word n-grams and an LCS for ROUGE-L.

All functions operate on plain strings and are deterministic.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

_TOKEN = re.compile(r"[a-z0-9]+")
PHASES = ("Explore", "Experiment", "Exploit")

# mteval-v13a tokenisation, transcribed from sacrebleu's Tokenizer13a so BLEU is
# directly comparable with that tool. Punctuation becomes its own token, which is
# what makes "1." and "<img>" count consistently between flows.
_13A_RULES = (
    (re.compile(r"([\{-\~\[-\` -\&\(-\+\:-\@\/])"), r" \1 "),
    (re.compile(r"([^0-9])([\.,])"), r"\1 \2 "),
    (re.compile(r"([\.,])([^0-9])"), r" \1 \2"),
    (re.compile(r"([0-9])(-)"), r"\1 \2 "),
)


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokens (same convention as the retrieval module)."""
    return _TOKEN.findall((text or "").lower())


def tokenize_13a(text: str) -> list[str]:
    """mteval-v13a tokens, lowercased (BLEU uses these; ROUGE uses ``tokenize``)."""
    line = (text or "").replace("<skipped>", "").replace("-\n", "").replace("\n", " ")
    if "&" in line:
        line = (
            line.replace("&quot;", '"')
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
        )
    line = f" {line} "
    for pattern, replacement in _13A_RULES:
        line = pattern.sub(replacement, line)
    return [token for token in line.lower().split() if token]


def _ngrams(tokens: Sequence[str], n: int) -> Counter[tuple[str, ...]]:
    if n <= 0 or len(tokens) < n:
        return Counter()
    return Counter(tuple(tokens[index : index + n]) for index in range(len(tokens) - n + 1))


def _bleu_statistics(
    candidates: Sequence[str],
    references: Sequence[str],
    *,
    max_n: int,
    smooth: bool,
    effective_order: bool,
) -> dict[str, float]:
    """Aggregate n-gram counts and turn them into precisions + log-sum.

    Mirrors sacrebleu: the smooth multiplier starts at 1 and doubles only when a
    zero count is hit, giving ``1 / (2**k * total_n)`` where ``k`` counts the
    zero-count orders seen so far.
    """
    correct = [0] * max_n
    total = [0] * max_n
    for candidate, reference in zip(candidates, references):
        candidate_tokens = tokenize_13a(candidate)
        reference_tokens = tokenize_13a(reference)
        for n in range(1, max_n + 1):
            candidate_counts = _ngrams(candidate_tokens, n)
            reference_counts = _ngrams(reference_tokens, n)
            correct[n - 1] += sum(
                min(count, reference_counts[gram]) for gram, count in candidate_counts.items()
            )
            total[n - 1] += sum(candidate_counts.values())

    precisions = {f"p{n}": 0.0 for n in range(1, max_n + 1)}
    result = {"log_sum": 0.0, "order": max_n, "valid": False, **precisions}

    # sacrebleu returns 0.0 outright when nothing matched at any order.
    if not any(correct):
        return result

    smooth_multiplier = 1.0
    order = max_n
    log_sum = 0.0
    for n in range(1, max_n + 1):
        if total[n - 1] == 0:
            break
        if effective_order:
            order = n
        if correct[n - 1] == 0:
            if smooth:
                smooth_multiplier *= 2
                precision = 1.0 / (smooth_multiplier * total[n - 1])
            else:
                precision = 0.0
        else:
            precision = correct[n - 1] / total[n - 1]
        result[f"p{n}"] = precision
        if precision <= 0.0:
            result["log_sum"] = 0.0
            result["valid"] = False
            return result
        log_sum += math.log(precision)

    result["log_sum"] = log_sum
    result["order"] = order
    # A perfect match has log(1.0) == 0.0 at every order, so a zero log-sum is
    # only a failure when it was marked as such -- never infer it from the value.
    result["valid"] = True
    return result


def _brevity_penalty(candidate_length: int, reference_length: int) -> float:
    if candidate_length == 0 or reference_length == 0:
        return 0.0
    if candidate_length >= reference_length:
        return 1.0
    return math.exp(1 - reference_length / candidate_length)


def bleu(
    candidate: str,
    reference: str,
    *,
    max_n: int = 4,
    smooth: bool = True,
    effective_order: bool = False,
) -> dict[str, float]:
    """Sentence BLEU (Papineni et al., 2002), sacrebleu-compatible.

    With ``effective_order=False`` (the default, matching sacrebleu's corpus
    behaviour) a candidate shorter than ``max_n`` tokens cannot score above 0.0.
    That is expected, not a bug: it is why generated flows should be compared
    with corpus BLEU as well as sentence BLEU.
    """
    candidate_tokens = tokenize_13a(candidate)
    reference_tokens = tokenize_13a(reference)
    if not candidate_tokens or not reference_tokens:
        return {"bleu": 0.0, **{f"p{n}": 0.0 for n in range(1, max_n + 1)}, "bp": 0.0}

    stats = _bleu_statistics(
        [candidate], [reference], max_n=max_n, smooth=smooth, effective_order=effective_order
    )
    brevity = _brevity_penalty(len(candidate_tokens), len(reference_tokens))
    score = 0.0 if not stats["valid"] else brevity * math.exp(stats["log_sum"] / stats["order"])
    return {
        "bleu": score,
        **{f"p{n}": stats[f"p{n}"] for n in range(1, max_n + 1)},
        "bp": brevity,
    }


def corpus_bleu(
    candidates: Sequence[str],
    references: Sequence[str],
    *,
    max_n: int = 4,
    smooth: bool = True,
    effective_order: bool = False,
) -> dict[str, float]:
    """Corpus BLEU: counts pooled over all sentences, one brevity penalty."""
    if len(candidates) != len(references):
        raise ValueError("candidates and references must have the same length")
    if not candidates:
        return {"bleu": 0.0, **{f"p{n}": 0.0 for n in range(1, max_n + 1)}, "bp": 0.0}

    stats = _bleu_statistics(
        candidates, references, max_n=max_n, smooth=smooth, effective_order=effective_order
    )
    candidate_length = sum(len(tokenize_13a(text)) for text in candidates)
    reference_length = sum(len(tokenize_13a(text)) for text in references)
    brevity = _brevity_penalty(candidate_length, reference_length)
    score = 0.0 if not stats["valid"] else brevity * math.exp(stats["log_sum"] / stats["order"])
    return {
        "bleu": score,
        **{f"p{n}": stats[f"p{n}"] for n in range(1, max_n + 1)},
        "bp": brevity,
    }


def _lcs_length(left: Sequence[str], right: Sequence[str]) -> int:
    if not left or not right:
        return 0
    previous = [0] * (len(right) + 1)
    for item in left:
        current = [0]
        for index, other in enumerate(right, start=1):
            if item == other:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(previous[index], current[index - 1]))
        previous = current
    return previous[-1]


def rouge_n(candidate: str, reference: str, n: int = 1) -> dict[str, float]:
    """ROUGE-N recall/precision/F1 over word n-grams (Lin, 2004)."""
    candidate_counts = _ngrams(tokenize(candidate), n)
    reference_counts = _ngrams(tokenize(reference), n)
    overlap = sum(min(count, reference_counts[gram]) for gram, count in candidate_counts.items())
    candidate_total = sum(candidate_counts.values())
    reference_total = sum(reference_counts.values())
    recall = overlap / reference_total if reference_total else 0.0
    precision = overlap / candidate_total if candidate_total else 0.0
    f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def rouge_l(candidate: str, reference: str) -> dict[str, float]:
    """ROUGE-L using the longest common subsequence."""
    candidate_tokens = tokenize(candidate)
    reference_tokens = tokenize(reference)
    lcs = _lcs_length(candidate_tokens, reference_tokens)
    recall = lcs / len(reference_tokens) if reference_tokens else 0.0
    precision = lcs / len(candidate_tokens) if candidate_tokens else 0.0
    f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def repetition_rate(text: str, n: int = 3) -> float:
    """Share of repeated n-grams: ``1 - unique/total``.

    A flow that emits the same sentence five times scores near 1.0; unique text
    scores 0.0. Text shorter than ``n`` tokens scores 0.0 by definition.
    """
    tokens = tokenize(text)
    if len(tokens) < n:
        return 0.0
    grams = list(zip(*(tokens[index:] for index in range(n))))
    if not grams:
        return 0.0
    return 1.0 - (len(set(grams)) / len(grams))


_PHASE_MARKER = re.compile(r"(?:^|\s)(?:\d{1,2}\.\s*)?(Explore|Experiment|Exploit)\s*:\s*")


def extract_phase_sequence(text: str) -> list[str]:
    """Ordered phase labels appearing in a generated flow."""
    return [match.group(1) for match in _PHASE_MARKER.finditer(text or "")]


def phase_order_accuracy(candidate: str, reference: str) -> float:
    """1.0 when the candidate phase sequence equals the reference's, else 0.0.

    Strict: a repeated phase (``Explore, Experiment, Experiment, Exploit``)
    breaks the match even though the skeleton is right. Reported alongside
    :func:`phase_order_accuracy_dedup` so the two failure modes - wrong skeleton
    vs. right skeleton with repetition - are not conflated.
    """
    reference_phases = extract_phase_sequence(reference)
    if not reference_phases:
        return 0.0
    return 1.0 if extract_phase_sequence(candidate) == reference_phases else 0.0


def _collapse_repeats(sequence: Sequence[str]) -> list[str]:
    collapsed: list[str] = []
    for item in sequence:
        if not collapsed or collapsed[-1] != item:
            collapsed.append(item)
    return collapsed


def phase_order_accuracy_dedup(candidate: str, reference: str) -> float:
    """Like :func:`phase_order_accuracy` but consecutive repeats are collapsed.

    This isolates "did the model produce the three phases in order" from "did it
    loop". A candidate of ``Explore, Experiment, Experiment, Exploit`` scores
    1.0 here and 0.0 on the strict metric.
    """
    reference_phases = _collapse_repeats(extract_phase_sequence(reference))
    if not reference_phases:
        return 0.0
    return 1.0 if _collapse_repeats(extract_phase_sequence(candidate)) == reference_phases else 0.0


def phase_coverage(candidate: str) -> float:
    """Share of the three phases that appear at least once (0, 1/3, 2/3 or 1)."""
    present = set(extract_phase_sequence(candidate))
    return len(present & set(PHASES)) / len(PHASES)


def missing_phases(candidate: str) -> list[str]:
    """Phases absent from the candidate, in canonical order."""
    present = set(extract_phase_sequence(candidate))
    return [phase for phase in PHASES if phase not in present]


def output_validity(candidate: str) -> float:
    """1.0 when the text is non-empty and all three phases appear."""
    if not (candidate or "").strip():
        return 0.0
    return 1.0 if not missing_phases(candidate) else 0.0


def _steps_by_phase(text: str) -> dict[str, list[str]]:
    """Slice a flow into per-phase step bodies using the phase markers."""
    markers = list(_PHASE_MARKER.finditer(text or ""))
    result: dict[str, list[str]] = {}
    for index, marker in enumerate(markers):
        start = marker.end()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(text or "")
        body = " ".join((text or "")[start:end].split())
        if body:
            result.setdefault(marker.group(1), []).append(body)
    return result


def phase_step_recall(candidate: str, reference: str, phase: str) -> float | None:
    """Share of reference steps of ``phase`` that the candidate also covers.

    A candidate step covers a reference step when it shares at least 50% of the
    reference step's tokens. Crude but deterministic and explainable; reported
    only as a per-phase diagnostic. ``None`` when the reference has no step in
    that phase, so callers can exclude the case instead of averaging a fake 0.
    """
    reference_steps = _steps_by_phase(reference).get(phase, [])
    if not reference_steps:
        return None
    candidate_token_sets = [
        set(tokenize(step)) for step in _steps_by_phase(candidate).get(phase, [])
    ]
    covered = 0
    for reference_step in reference_steps:
        reference_tokens = set(tokenize(reference_step))
        if not reference_tokens:
            continue
        if any(
            len(reference_tokens & item) / len(reference_tokens) >= 0.5
            for item in candidate_token_sets
        ):
            covered += 1
    return covered / len(reference_steps)


def unigram_f1(candidate: str, reference: str) -> float:
    """Kept from the Phase-1 scaffold: simple token overlap F1."""
    candidate_tokens = tokenize(candidate)
    reference_tokens = tokenize(reference)
    if not candidate_tokens or not reference_tokens:
        return 0.0
    candidate_counts = Counter(candidate_tokens)
    reference_counts = Counter(reference_tokens)
    overlap = sum((candidate_counts & reference_counts).values())
    precision = overlap / len(candidate_tokens)
    recall = overlap / len(reference_tokens)
    return 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)


def score_flow(candidate: str, reference: str) -> dict[str, float | None]:
    """All per-case metrics in one dict (used by the evaluation harness)."""
    sentence = bleu(candidate, reference)
    return {
        "bleu": sentence["bleu"],
        "rouge1": rouge_n(candidate, reference, 1)["f1"],
        "rouge2": rouge_n(candidate, reference, 2)["f1"],
        "rougeL": rouge_l(candidate, reference)["f1"],
        "phase_order_accuracy": phase_order_accuracy(candidate, reference),
        "phase_order_accuracy_dedup": phase_order_accuracy_dedup(candidate, reference),
        "phase_coverage": phase_coverage(candidate),
        "output_validity": output_validity(candidate),
        "repetition_rate": repetition_rate(candidate),
        "missing_phases": float(len(missing_phases(candidate))),
        "unigram_f1": unigram_f1(candidate, reference),
        "phase_recall_explore": phase_step_recall(candidate, reference, "Explore"),
        "phase_recall_experiment": phase_step_recall(candidate, reference, "Experiment"),
        "phase_recall_exploit": phase_step_recall(candidate, reference, "Exploit"),
    }
