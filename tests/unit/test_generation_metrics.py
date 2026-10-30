"""Generation metrics: BLEU/ROUGE correctness, phase checks, and repetition.

BLEU is asserted against values produced by ``sacrebleu`` and ROUGE against
``rouge_score`` for the same inputs, so a future refactor cannot silently drift
away from the standard tools. Those expected numbers are constants here rather
than a test-time dependency, keeping CI free of the extra packages.
"""

import pytest

from evaluation.generation.metrics import (
    PHASES,
    bleu,
    corpus_bleu,
    extract_phase_sequence,
    missing_phases,
    output_validity,
    phase_coverage,
    phase_order_accuracy,
    phase_order_accuracy_dedup,
    phase_step_recall,
    repetition_rate,
    rouge_l,
    rouge_n,
    score_flow,
    tokenize,
    tokenize_13a,
)

FLOW = (
    "CAPEC-66 SQL Injection\n"
    "1. Explore: Survey the application for inputs.\n"
    "2. Experiment: Probe with quote characters.\n"
    "3. Exploit: Extract data with a tautology.\n"
)


def test_tokenizers_differ_on_punctuation():
    assert tokenize("1. Explore: x") == ["1", "explore", "x"]
    # 13a separates punctuation into its own tokens (verified against sacrebleu).
    assert tokenize_13a("1. Explore: x") == ["1", ".", "explore", ":", "x"]


def test_bleu_perfect_match_is_one():
    assert bleu(FLOW, FLOW)["bleu"] == pytest.approx(1.0)


def test_bleu_matches_sacrebleu_reference_values():
    """Expected values come from sacrebleu sentence_bleu(smooth_method='exp')."""
    cases = [
        ("the cat sat on the mat today", "the cat sat on the mat", 80.911),
        (
            "a quick brown fox jumps over the lazy dog",
            "a quick brown fox jumps over a lazy dog",
            66.063,
        ),
        (
            "explore the app then experiment then exploit",
            "explore the application experiment with input exploit the flaw",
            11.738,
        ),
        ("x y z", "a b c", 0.0),
    ]
    for candidate, reference, expected in cases:
        assert bleu(candidate, reference)["bleu"] * 100 == pytest.approx(expected, abs=0.01)


def test_corpus_bleu_matches_sacrebleu_reference_value():
    candidates = [
        "the cat sat on the mat today",
        "a quick brown fox jumps over the lazy dog",
        "identical words here for testing",
    ]
    references = [
        "the cat sat on the mat",
        "a quick brown fox jumps over a lazy dog",
        "identical words here for testing",
    ]
    # sacrebleu.corpus_bleu(...) == 77.919 for this triple.
    assert corpus_bleu(candidates, references)["bleu"] * 100 == pytest.approx(77.919, abs=0.01)


def test_corpus_bleu_requires_equal_lengths():
    with pytest.raises(ValueError):
        corpus_bleu(["a"], [])


def test_rouge_matches_rouge_score_reference_values():
    case = (
        "explore the app experiment with input exploit the flaw",
        "explore the application experiment with input and exploit the flaw",
    )
    candidate, reference = case
    assert rouge_n(candidate, reference, 1)["f1"] == pytest.approx(0.8421, abs=1e-4)
    assert rouge_n(candidate, reference, 2)["f1"] == pytest.approx(0.5882, abs=1e-4)
    assert rouge_l(candidate, reference)["f1"] == pytest.approx(0.8421, abs=1e-4)


def test_rouge_identical_is_one():
    assert rouge_n(FLOW, FLOW, 1)["f1"] == pytest.approx(1.0)
    assert rouge_n(FLOW, FLOW, 2)["f1"] == pytest.approx(1.0)
    assert rouge_l(FLOW, FLOW)["f1"] == pytest.approx(1.0)


def test_rouge_handles_empty_input():
    assert rouge_n("", "a b", 1) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    assert rouge_l("a b", "")["f1"] == 0.0


def test_repetition_rate_detects_loops():
    looped = "survey the app " * 5
    assert repetition_rate(looped) > 0.5
    assert repetition_rate("alpha beta gamma delta epsilon zeta theta") == 0.0


def test_repetition_rate_is_zero_for_short_text():
    assert repetition_rate("two words") == 0.0


def test_phase_sequence_extraction():
    assert extract_phase_sequence(FLOW) == list(PHASES)
    assert extract_phase_sequence("no markers here") == []


def test_missing_phases_and_validity():
    assert missing_phases(FLOW) == []
    assert output_validity(FLOW) == 1.0
    partial = "1. Explore: only this"
    assert missing_phases(partial) == ["Experiment", "Exploit"]
    assert output_validity(partial) == 0.0
    assert output_validity("") == 0.0


def test_phase_coverage_counts_present_phases():
    assert phase_coverage(FLOW) == 1.0
    assert phase_coverage("1. Explore: a 2. Exploit: b") == pytest.approx(2 / 3)


def test_strict_phase_order_rejects_repetition_but_dedup_accepts_it():
    repeated = "1. Explore: a 2. Experiment: b 3. Experiment: c 4. Exploit: d"
    reference = "1. Explore: a 2. Experiment: b 3. Exploit: c"
    assert phase_order_accuracy(repeated, reference) == 0.0
    assert phase_order_accuracy_dedup(repeated, reference) == 1.0


def test_phase_order_accuracy_requires_a_reference_sequence():
    assert phase_order_accuracy(FLOW, "no phases") == 0.0
    assert phase_order_accuracy_dedup(FLOW, "no phases") == 0.0


def test_phase_step_recall_is_none_when_reference_lacks_phase():
    reference = "1. Explore: survey the app 2. Exploit: run"
    assert phase_step_recall(FLOW, reference, "Experiment") is None


def test_phase_step_recall_measures_coverage():
    reference = "1. Explore: Survey the application for inputs."
    candidate = "1. Explore: Survey the application for inputs now."
    assert phase_step_recall(candidate, reference, "Explore") == 1.0


def test_score_flow_exposes_every_metric():
    scores = score_flow(FLOW, FLOW)
    for key in (
        "bleu",
        "rouge1",
        "rouge2",
        "rougeL",
        "phase_order_accuracy",
        "phase_order_accuracy_dedup",
        "phase_coverage",
        "output_validity",
        "repetition_rate",
        "missing_phases",
        "unigram_f1",
        "phase_recall_explore",
        "phase_recall_experiment",
        "phase_recall_exploit",
    ):
        assert key in scores
    assert scores["bleu"] == pytest.approx(1.0)
    assert scores["output_validity"] == 1.0
