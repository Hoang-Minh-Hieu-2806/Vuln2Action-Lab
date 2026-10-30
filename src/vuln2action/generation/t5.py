"""Local T5 execution-flow generator (P1.1).

Replaces the previous stub. A fine-tuned ``t5-small`` checkpoint is loaded
lazily, prompted with the same task prefix used at training time, and its output
is parsed into a :class:`~vuln2action.domain.Workflow` so the rest of the
pipeline is unchanged.

Design notes
------------
* ``torch``/``transformers`` are **optional**. Importing this module is always
  safe; the heavy imports happen only when a model is first needed.
* Nothing is downloaded unless ``allow_download`` is set. Without it, loading a
  checkpoint that is not already cached raises a clear, actionable error.
* The emitted text is *guidance*, not a validated exploit. Every workflow says so
  in its ``safety`` field and the model is never asked for executable payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vuln2action.config import T5ProviderSettings, load_model_settings
from vuln2action.domain import CveRecord, RetrievedContext, Workflow, WorkflowStep
from vuln2action.generation.base import GenerationProvider
from vuln2action.generation.prompts import build_context_summary

TASK_PREFIX = "Generate the Explore/Experiment/Exploit attack flow for this weakness: "
PHASES = ("Explore", "Experiment", "Exploit")
PHASE_RANK = {phase: index for index, phase in enumerate(PHASES)}
_SAFETY = "generated guidance only; not a validated exploit and not for real-world targets"
# Small T5 checkpoints often drop the newlines and step numbers they were trained
# on, so the marker is matched anywhere in the text and the index is optional.
_STEP_MARKER = re.compile(r"(?:^|\s)(?:\d{1,2}\.\s*)?(Explore|Experiment|Exploit)\s*:\s*")


class T5UnavailableError(RuntimeError):
    """Raised when the optional T5 stack or a checkpoint is not available."""


def require_t5_stack() -> None:
    """Fail fast with an actionable message when the optional deps are absent."""
    try:  # pragma: no cover - exercised only without the extras installed
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise T5UnavailableError(
            "The T5 generator needs the optional deep-learning extras. "
            'Install them with: python -m pip install -e ".[t5]"'
        ) from exc


def build_model_input(cve: CveRecord, contexts: list[RetrievedContext]) -> str:
    """Compose the model input; mirrors ``scripts/build_t5_dataset.py``."""
    parts = [TASK_PREFIX, f"{cve.cve_id}."]
    if cve.description:
        parts.append(cve.description)
    if cve.cwe:
        parts.append("Weaknesses: " + ", ".join(cve.cwe) + ".")
    patterns = [
        context.source for context in contexts if context.source.upper().startswith("CAPEC-")
    ]
    if patterns:
        parts.append("Candidate attack patterns: " + ", ".join(sorted(set(patterns))) + ".")
    return " ".join(parts)


@dataclass
class GeneratedFlow:
    """Raw generation result before it is shaped into a Workflow."""

    text: str
    checkpoint: str
    steps: list[dict[str, Any]] = field(default_factory=list)


def parse_flow(text: str) -> list[dict[str, Any]]:
    """Parse ``N. Phase: description`` markers into steps.

    The marker is found anywhere in the text because small checkpoints frequently
    emit the whole flow on one line. Repeated phases emitted back to back are
    kept (they are what the model produced); callers can dedupe if they want.
    """
    source = text or ""
    markers = list(_STEP_MARKER.finditer(source))
    steps: list[dict[str, Any]] = []
    for index, marker in enumerate(markers):
        start = marker.end()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(source)
        body = " ".join(source[start:end].split())
        if not body:
            continue
        steps.append(
            {
                "phase": marker.group(1),
                "description": body,
                "techniques": [],
            }
        )
    return steps


def normalise_flow_structure(text: str) -> tuple[str, dict[str, Any]]:
    """Enforce Explore → Experiment → Exploit ordering *without changing content*.

    Only one repair is applied: a phase that appears *after* a later phase
    (e.g. an ``Explore`` emitted following ``Experiment``) is moved to its
    canonical position. Steps are never dropped, merged, or invented — MITRE
    flows legitimately contain several steps in one phase (two ``Experiment``
    steps is normal), so collapsing repeats would silently delete content.

    Repetition is a *decoding* problem (see ``no_repeat_ngram_size``), not a
    post-processing one. Returns the text plus a report of what changed.
    """
    parsed = parse_flow(text)
    report: dict[str, Any] = {
        "original_phases": [item["phase"] for item in parsed],
        "reordered_steps": 0,
        "dropped_steps": 0,
        "inserted_phases": [],  # always empty by design
    }
    if not parsed:
        return text, report

    # Stable sort by canonical phase rank: keeps the model's own step order
    # inside each phase and never removes a step.
    ordered = sorted(parsed, key=lambda item: PHASE_RANK[item["phase"]])
    if [item["phase"] for item in ordered] == report["original_phases"]:
        return text, report

    report["reordered_steps"] = sum(
        1 for original, fixed in zip(parsed, ordered) if original is not fixed
    )
    report["final_phases"] = [item["phase"] for item in ordered]
    header = text.split("\n", 1)[0].strip()
    lines = [header]
    for index, item in enumerate(ordered, start=1):
        lines.append(f"{index}. {item['phase']}: {item['description']}")
    return "\n".join(lines), report


def flow_to_workflow(
    text: str,
    cve: CveRecord,
    contexts: list[RetrievedContext],
    *,
    provider: str = "t5",
    lab_id: str = "",
    normalise: bool = True,
) -> Workflow:
    """Convert generated text into the pipeline's typed Workflow.

    With ``normalise`` (the default) the phase skeleton is repaired as described
    in :func:`normalise_flow_structure`; missing phases are reported through the
    ``safety`` field and the step list, never filled in. A model that emits
    unparseable text still produces a valid Workflow: the raw output is preserved
    as a single ``review`` step so nothing is silently lost.
    """
    source_text = text
    if normalise:
        source_text, _ = normalise_flow_structure(text)

    parsed = parse_flow(source_text)
    steps: list[WorkflowStep] = []
    if parsed:
        for index, item in enumerate(parsed, start=1):
            steps.append(
                WorkflowStep(
                    id=f"{item['phase'].lower()}-{index}",
                    action=f"{item['phase']} step",
                    detail=item["description"][:1200],
                )
            )
    else:
        steps.append(
            WorkflowStep(
                id="review",
                action="Review raw model output",
                detail=(text or "(empty generation)").strip()[:800],
            )
        )

    produced = {item["phase"] for item in parsed}
    absent = [phase for phase in PHASES if phase not in produced]
    safety = _SAFETY if not absent else f"{_SAFETY}; missing phases: {', '.join(absent)}"

    return Workflow(
        cve_id=cve.cve_id,
        provider=provider,
        lab_id=lab_id or cve.lab_id,
        context_summary=build_context_summary(contexts),
        safety=safety,
        steps=steps,
    )


class T5Generator(GenerationProvider):
    """Seq2seq generator backed by a local (optionally fine-tuned) T5."""

    name = "t5"

    def __init__(
        self,
        settings: T5ProviderSettings | None = None,
        *,
        checkpoint: str | Path | None = None,
        model: Any | None = None,
        tokenizer: Any | None = None,
    ) -> None:
        self.settings = settings or load_model_settings().providers.t5
        chosen = checkpoint if checkpoint is not None else self.settings.checkpoint
        self.checkpoint = str(chosen or self.settings.base_checkpoint)
        self._model = model
        self._tokenizer = tokenizer

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._tokenizer is not None

    def _local_only(self) -> bool | None:
        return None if self.settings.allow_download else True

    def _ensure_loaded(self) -> None:
        if self.is_loaded:
            return
        require_t5_stack()
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

        local_only = self._local_only()
        try:
            tokenizer = AutoTokenizer.from_pretrained(self.checkpoint, local_files_only=local_only)
            model = AutoModelForSeq2SeqLM.from_pretrained(
                self.checkpoint, local_files_only=local_only
            )
        except (OSError, ValueError) as exc:
            hint = (
                "Set `allow_download: true` in config/models.yaml to fetch it, "
                'or run `python -m pip install -e ".[t5]"` first.'
            )
            raise T5UnavailableError(
                f"Could not load T5 checkpoint {self.checkpoint!r}: {exc}. {hint}"
            ) from exc
        model.eval()
        self._tokenizer = tokenizer
        self._model = model

    def _generation_kwargs(self) -> dict[str, Any]:
        """Translate settings into ``generate()`` kwargs.

        ``no_repeat_ngram_size`` and ``repetition_penalty`` are the two knobs that
        address the measured failure (a step body looping until the token cap is
        hit, which truncates the flow before Exploit). Both are omitted when left
        at their neutral defaults so an untouched config reproduces P1.2 exactly.
        """
        kwargs: dict[str, Any] = {
            "max_new_tokens": self.settings.max_new_tokens,
            "num_beams": self.settings.num_beams,
            "do_sample": False,
        }
        if self.settings.no_repeat_ngram_size:
            kwargs["no_repeat_ngram_size"] = self.settings.no_repeat_ngram_size
        if self.settings.repetition_penalty and self.settings.repetition_penalty != 1.0:
            kwargs["repetition_penalty"] = self.settings.repetition_penalty
        if self.settings.length_penalty != 1.0:
            kwargs["length_penalty"] = self.settings.length_penalty
        if self.settings.early_stopping:
            kwargs["early_stopping"] = True
        if self.settings.min_new_tokens:
            kwargs["min_new_tokens"] = self.settings.min_new_tokens
        return kwargs

    def generate_flow(self, cve: CveRecord, contexts: list[RetrievedContext]) -> GeneratedFlow:
        self._ensure_loaded()
        import torch

        prompt = build_model_input(cve, contexts)
        inputs = self._tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=self.settings.max_input_length,
        )
        with torch.no_grad():
            output = self._model.generate(**inputs, **self._generation_kwargs())
        text = self._tokenizer.decode(output[0], skip_special_tokens=True)
        return GeneratedFlow(text=text, checkpoint=self.checkpoint, steps=parse_flow(text))

    def generate(self, cve: CveRecord, contexts: list[RetrievedContext]) -> Workflow:
        flow = self.generate_flow(cve, contexts)
        return flow_to_workflow(
            flow.text,
            cve,
            contexts,
            provider=self.name,
            normalise=self.settings.normalise_output,
        )
