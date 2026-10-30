"""Evaluate execution-flow generation: fine-tuned T5 vs the rule-based baseline.

Design rules
------------
* **Same cases, same references.** Every system is scored on the identical
  held-out set against the same MITRE-derived target flows.
* **Leakage first, metrics second.** The dataset's hash split controls CAPEC ids
  but not *text*: sibling patterns (CAPEC-52/53, 143/144, 33/105) share nearly
  identical MITRE prose. This module detects those clusters and reports metrics
  on both the full validation set and a leakage-free subset.
* **Rule-based is a baseline, not a rival.** It was built for lab workflows, not
  CAPEC prose, so its low BLEU is expected; the point is to show that the
  metric separates the two systems rather than to rank them.
* **No retraining.** The harness only loads checkpoints that already exist.
* **Never imply an untrained model is fine-tuned.** Each system states whether
  its checkpoint came from ``scripts/train_t5.py`` or is the raw base model.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import re
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_ROOT = Path(__file__).resolve().parents[2]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from evaluation.generation.metrics import PHASES, corpus_bleu, missing_phases, score_flow
from vuln2action.config import load_model_settings, project_root
from vuln2action.domain import CveRecord, Workflow
from vuln2action.generation.rule_based import RuleBasedGenerator
from vuln2action.utils.filesystem import ensure_dir, read_json, write_json

DEFAULT_DATASET = "data/processed/t5_flows.json"
DEFAULT_CHECKPOINT = "models/t5-capec-flows"
NEAR_DUPLICATE_THRESHOLD = 0.85


class DatasetMissingError(RuntimeError):
    """Raised when the training dataset has not been built."""


class FlowCase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    capec_id: str
    name: str
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    input_text: str
    target_flow: str
    steps: list[dict[str, Any]] = Field(default_factory=list)


class FlowDataset(BaseModel):
    # The builder writes extra bookkeeping fields (counts, phase tallies) that the
    # evaluator does not need; ignore them rather than rejecting the file.
    model_config = ConfigDict(extra="ignore")
    version: str = "1.0.0"
    description: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    seed: int = 13
    validation_fraction: float = 0.15
    train: list[FlowCase] = Field(default_factory=list)
    validation: list[FlowCase] = Field(default_factory=list)


def load_flow_dataset(path: str | Path | None = None) -> FlowDataset:
    resolved = Path(path) if path else project_root() / DEFAULT_DATASET
    if not resolved.is_file():
        raise DatasetMissingError(
            f"Dataset not found: {resolved}. Run: python scripts/build_t5_dataset.py"
        )
    return FlowDataset.model_validate(read_json(resolved))


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def audit_leakage(
    train: Sequence[FlowCase],
    validation: Sequence[FlowCase],
    *,
    threshold: float = NEAR_DUPLICATE_THRESHOLD,
) -> dict[str, Any]:
    """Detect id overlap, exact duplicates and near-identical flows.

    Near-duplication is measured with ``difflib`` ratio on normalised text. The
    threshold is a judgement call, so every flagged pair is returned with its
    score instead of only a count.
    """
    train_ids = {case.capec_id for case in train}
    validation_ids = {case.capec_id for case in validation}
    exact_targets = Counter(_normalise(case.target_flow) for case in train)

    exact_duplicates = [
        c.capec_id for c in validation if _normalise(c.target_flow) in exact_targets
    ]
    near_duplicates: list[dict[str, Any]] = []
    for case in validation:
        candidate_text = _normalise(case.target_flow)
        best_ratio = 0.0
        best_train: FlowCase | None = None
        for other in train:
            other_text = _normalise(other.target_flow)
            if difflib.SequenceMatcher(None, candidate_text, other_text).quick_ratio() < threshold:
                continue
            ratio = difflib.SequenceMatcher(None, candidate_text, other_text).ratio()
            if ratio > best_ratio:
                best_ratio, best_train = ratio, other
        if best_train is not None and best_ratio >= threshold:
            near_duplicates.append(
                {
                    "validation_case": case.capec_id,
                    "validation_name": case.name,
                    "train_case": best_train.capec_id,
                    "train_name": best_train.name,
                    "similarity": round(best_ratio, 4),
                    "shares_cwe": bool(set(case.cwe_ids) & set(best_train.cwe_ids)),
                }
            )

    leaked = {item["validation_case"] for item in near_duplicates} | set(exact_duplicates)
    clean = [case.capec_id for case in validation if case.capec_id not in leaked]
    return {
        "threshold": threshold,
        "train_cases": len(train),
        "validation_cases": len(validation),
        "capec_id_overlap": sorted(train_ids & validation_ids),
        "exact_duplicate_targets": sorted(exact_duplicates),
        "near_duplicates": sorted(near_duplicates, key=lambda item: -item["similarity"]),
        "leaked_validation_cases": sorted(leaked),
        "clean_validation_cases": clean,
        "clean_validation_count": len(clean),
        "verdict": (
            "no leakage detected"
            if not leaked
            else f"{len(leaked)} of {len(validation)} validation cases overlap the train set"
        ),
    }


def _cve_for(case: FlowCase) -> CveRecord:
    """Adapt a CAPEC flow case to the CveRecord the generators accept."""
    return CveRecord(
        cve_id=case.capec_id,
        description=case.input_text,
        cwe=list(case.cwe_ids),
    )


def _workflow_text(workflow: Workflow, *, name: str = "") -> str:
    """Render a generated Workflow in the same shape as the dataset targets.

    The first line mirrors the target format `<id> <pattern name>`. The name
    comes from the *case metadata*, not from the model, so this does not leak
    generated content into the scores - it only avoids an artificial penalty for
    a header the model was never asked to reproduce verbatim.
    """
    header = f"{workflow.cve_id} {name}".strip() if name else f"{workflow.cve_id}"
    lines = [header]
    for index, step in enumerate(workflow.steps, start=1):
        phase = step.id.split("-", 1)[0].capitalize()
        if phase in PHASES:
            lines.append(f"{index}. {phase}: {step.detail}")
        else:
            lines.append(f"{index}. {step.action}: {step.detail}")
    return "\n".join(lines)


def system_metadata(
    name: str,
    *,
    checkpoint: str,
    fine_tuned: bool,
    base: str = "",
    decoding: str = "n/a",
) -> dict[str, Any]:
    return {
        "system": name,
        "kind": "fine-tuned" if fine_tuned else "baseline",
        "fine_tuned": fine_tuned,
        "checkpoint": checkpoint,
        "base_checkpoint": base,
        "decoding": decoding,
        "decoding_settings": DECODING_PRESETS.get(decoding, {}),
        "note": (
            "checkpoint produced by scripts/train_t5.py"
            if fine_tuned
            else "not fine-tuned: outputs are the stock template or base model"
        ),
    }


def _aggregate(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Mean of every numeric per-case metric, skipping undefined phase recalls."""
    if not rows:
        return {"cases": 0}
    keys = [
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
    ]
    summary: dict[str, Any] = {"cases": len(rows)}
    for key in keys:
        values = [row[key] for row in rows if row.get(key) is not None]
        summary[key] = sum(values) / len(values) if values else None
        summary[f"{key}_n"] = len(values)
    phases_seen = Counter()
    for row in rows:
        for phase in row.get("missing_phase_names", []):
            phases_seen[phase] += 1
    summary["missing_phase_counts"] = dict(phases_seen)
    return summary


def evaluate_system(
    system: str,
    cases: Sequence[FlowCase],
    generator,
    *,
    metadata: dict[str, Any],
    leakage_clean: set[str],
    failure_limit: int = 5,
) -> dict[str, Any]:
    """Score one generator over ``cases`` and return rows plus aggregates."""
    rows: list[dict[str, Any]] = []
    candidates: list[str] = []
    references: list[str] = []
    for case in cases:
        reference = case.target_flow
        cve = _cve_for(case)
        workflow = generator.generate(cve, [])
        candidate = _workflow_text(workflow, name=case.name)
        metrics = score_flow(candidate, reference)
        rows.append(
            {
                "case_id": case.capec_id,
                "name": case.name,
                "leakage_clean": case.capec_id in leakage_clean,
                "candidate": candidate,
                "reference": reference,
                "missing_phase_names": missing_phases(candidate),
                **metrics,
            }
        )
        candidates.append(candidate)
        references.append(reference)

    corpus = corpus_bleu(candidates, references)
    clean_rows = [row for row in rows if row["leakage_clean"]]
    failures = sorted(
        rows,
        key=lambda row: (row["bleu"], -row["repetition_rate"], row["phase_order_accuracy"]),
    )[:failure_limit]
    return {
        "system": metadata,
        "cases": len(rows),
        "corpus_bleu": corpus["bleu"],
        "corpus_bleu_precisions": {f"p{n}": corpus[f"p{n}"] for n in range(1, 5)},
        "brevity_penalty": corpus["bp"],
        "mean": _aggregate(rows),
        "phase_breakdown": {
            phase: _aggregate(
                [
                    {
                        **row,
                        f"phase_recall_{phase.lower()}": row.get(f"phase_recall_{phase.lower()}"),
                    }
                    for row in rows
                ]
            )
            for phase in PHASES
        },
        "leakage_clean": {
            "cases": len(clean_rows),
            "corpus_bleu": (
                corpus_bleu(
                    [row["candidate"] for row in clean_rows],
                    [row["reference"] for row in clean_rows],
                )["bleu"]
                if clean_rows
                else 0.0
            ),
            "mean": _aggregate(clean_rows),
        },
        "failures": failures,
        "rows": rows,
    }


def _comparison_table(report: dict[str, Any]) -> str:
    lines = [
        (
            f"dataset: {report['dataset']['validation_cases']} validation cases "
            f"| leakage: {report['leakage']['verdict']}"
        ),
        "",
        (
            f"{'system':<22} {'corpusBLEU':>11} {'BLEU':>7} {'R1':>6} {'R2':>6} {'RL':>6} "
            f"{'phase':>6} {'phDedup':>8} {'cov':>5} {'valid':>6} {'rep':>6}"
        ),
    ]
    for name, result in report["systems"].items():
        mean = result["mean"]
        lines.append(
            f"{name:<22} {result['corpus_bleu']:>11.4f} {mean['bleu']:>7.4f} "
            f"{mean['rouge1']:>6.4f} {mean['rouge2']:>6.4f} {mean['rougeL']:>6.4f} "
            f"{mean['phase_order_accuracy']:>6.4f} {mean['phase_order_accuracy_dedup']:>8.4f} "
            f"{mean['phase_coverage']:>5.4f} {mean['output_validity']:>6.4f} "
            f"{mean['repetition_rate']:>6.4f}"
        )
    lines.extend(["", "Leakage-free subset:"])
    for name, result in report["systems"].items():
        clean = result["leakage_clean"]
        if clean["cases"]:
            lines.append(
                f"  {name:<20} n={clean['cases']:<3} corpusBLEU={clean['corpus_bleu']:.4f} "
                f"BLEU={clean['mean']['bleu']:.4f} phase={clean['mean']['phase_order_accuracy']:.4f} "
                f"rep={clean['mean']['repetition_rate']:.4f}"
            )
        else:
            lines.append(f"  {name:<20} n=0 (all cases leaked)")
    return "\n".join(lines)


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Execution-flow generation evaluation",
        "",
        f"- Dataset: `{report['dataset']['path']}`",
        f"- Validation cases: {report['dataset']['validation_cases']}",
        f"- Leakage: {report['leakage']['verdict']}",
        f"- Near-duplicate threshold: {report['leakage']['threshold']}",
        "",
        "## Systems",
        "",
    ]
    for name, result in report["systems"].items():
        meta = result["system"]
        lines.append(
            f"- **{name}** ({meta['kind']}): checkpoint=`{meta['checkpoint']}` — {meta['note']}"
        )
    lines.extend(
        [
            "",
            "## Overall",
            "",
            "| System | Corpus BLEU | Sentence BLEU | ROUGE-1 | ROUGE-2 | ROUGE-L | Phase order | Phase order (dedup) | Phase coverage | Valid output | Repetition |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for name, result in report["systems"].items():
        mean = result["mean"]
        lines.append(
            f"| {name} | {result['corpus_bleu']:.4f} | {mean['bleu']:.4f} | "
            f"{mean['rouge1']:.4f} | {mean['rouge2']:.4f} | {mean['rougeL']:.4f} | "
            f"{mean['phase_order_accuracy']:.4f} | {mean['output_validity']:.4f} | "
            f"{mean['repetition_rate']:.4f} |"
        )
    lines.extend(["", "## Per phase (step recall)", ""])
    header = "| System | " + " | ".join(PHASES) + " |"
    lines.append(header)
    lines.append("| --- | " + " | ".join("---" for _ in PHASES) + " |")
    for name, result in report["systems"].items():
        cells = []
        for phase in PHASES:
            value = result["phase_breakdown"][phase].get(f"phase_recall_{phase.lower()}")
            cells.append("n/a" if value is None else f"{value:.4f}")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines.extend(["", "## Leakage-free subset", ""])
    for name, result in report["systems"].items():
        clean = result["leakage_clean"]
        lines.append(f"- {name}: n={clean['cases']}, corpus BLEU={clean['corpus_bleu']:.4f}")
    return "\n".join(lines) + "\n"


def _write_csv(path: Path, report: dict[str, Any]) -> Path:
    fieldnames = [
        "system",
        "case_id",
        "name",
        "leakage_clean",
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
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for name, result in report["systems"].items():
            for row in result["rows"]:
                writer.writerow({"system": name, **row})
    return path


def _safe_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


# Decoding presets. ``baseline`` reproduces the P1.2 setup exactly (no extra
# controls), so before/after is a like-for-like comparison on identical cases.
# ``improved`` adds n-gram blocking plus a length-aware beam search, which
# addresses the measured failure: a step body loops, hits the token cap and the
# flow never reaches Exploit.
DECODING_PRESETS: dict[str, dict[str, Any]] = {
    "baseline": {
        "max_new_tokens": 256,
        "num_beams": 4,
        "normalise_output": False,
    },
    # Chosen on the VALIDATION split only (see docs/generation-quality.md).
    # no_repeat_ngram_size stops the within-step loop; length_penalty=2.0 makes
    # beam search prefer the longer, complete flow, which restores the brevity
    # penalty that collapsing repeats would otherwise destroy.
    "improved": {
        "max_new_tokens": 512,
        "num_beams": 4,
        "no_repeat_ngram_size": 3,
        "repetition_penalty": 1.15,
        "length_penalty": 2.0,
        "early_stopping": True,
        "normalise_output": True,
    },
}


def _load_t5_generator(
    checkpoint: str,
    allow_download: bool,
    *,
    decoding: str = "baseline",
):
    from vuln2action.generation.t5 import T5Generator

    if decoding not in DECODING_PRESETS:
        raise ValueError(
            f"Unknown decoding preset: {decoding!r}. Choose from {sorted(DECODING_PRESETS)}"
        )
    settings = load_model_settings().providers.t5
    settings = settings.model_copy(
        update={
            "checkpoint": checkpoint,
            "allow_download": allow_download,
            **DECODING_PRESETS[decoding],
        }
    )
    return T5Generator(settings)


def _fine_tuned_checkpoint(checkpoint: str) -> bool:
    """A checkpoint counts as fine-tuned only when training actually recorded it."""
    summary = Path(checkpoint) / "training_summary.json"
    return summary.is_file()


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(description="Evaluate execution-flow generation.")
    parser.add_argument("--dataset", default=DEFAULT_DATASET, help="Dataset JSON.")
    parser.add_argument(
        "--systems",
        default="rule_based,t5-baseline,t5-improved",
        help="Comma-separated systems: rule_based, t5, t5-baseline, t5-improved, flan-t5.",
    )
    parser.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT, help="T5 checkpoint directory.")
    parser.add_argument(
        "--flan-checkpoint",
        default="google/flan-t5-small",
        help="Optional FLAN-T5 checkpoint (only used when --systems includes flan-t5).",
    )
    parser.add_argument("--limit", type=int, default=0, help="Evaluate only the first N cases.")
    parser.add_argument("--failures", type=int, default=5, help="Failure cases per system.")
    parser.add_argument("--save", default="", help="Output directory for JSON/CSV/Markdown.")
    parser.add_argument("--json-only", action="store_true", help="Print JSON only.")
    parser.add_argument(
        "--allow-download",
        action="store_true",
        help="Permit fetching checkpoints from the Hub (explicit opt-in).",
    )
    args = parser.parse_args(argv)

    if args.limit < 0:
        parser.error("--limit must be >= 0")
    requested = [name.strip() for name in args.systems.split(",") if name.strip()]
    if not requested:
        parser.error("at least one system is required")

    try:
        dataset = load_flow_dataset(args.dataset)
    except (DatasetMissingError, ValueError) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    validation = list(dataset.validation)
    if args.limit:
        validation = validation[: args.limit]
    if not validation:
        parser.error("validation split is empty; rebuild the dataset")
        return 2  # pragma: no cover

    leakage = audit_leakage(dataset.train, validation)
    clean = set(leakage["clean_validation_cases"])

    generators: dict[str, Any] = {}
    metadata: dict[str, dict[str, Any]] = {}
    for name in requested:
        key = name.lower()
        if key == "rule_based":
            generators["rule_based"] = RuleBasedGenerator()
            metadata["rule_based"] = system_metadata(
                "rule_based", checkpoint="(template)", fine_tuned=False
            )
        elif key in {
            "t5",
            "t5-baseline",
            "t5-improved",
            "flan-t5",
            "flan_t5",
        }:
            if key.startswith("t5"):
                checkpoint = args.checkpoint
                fine_tuned = _fine_tuned_checkpoint(checkpoint)
                decoding = key[len("t5-") :] if key.startswith("t5-") else "baseline"
                base = "t5-small"
            else:
                checkpoint = args.flan_checkpoint
                fine_tuned = False
                decoding = "baseline"
                base = "flan-t5-small"
            try:
                generators[key] = _load_t5_generator(
                    checkpoint, args.allow_download, decoding=decoding
                )
            except (RuntimeError, OSError) as exc:
                print(f"warning: skipping {name}: {exc}", file=sys.stderr)
                continue
            metadata[key] = system_metadata(
                key,
                checkpoint=checkpoint,
                fine_tuned=fine_tuned,
                base=base,
                decoding=decoding,
            )
        else:
            parser.error(f"unknown system: {name!r}")
            return 2  # pragma: no cover

    if not generators:
        parser.error("no usable systems were loaded")
        return 2  # pragma: no cover

    systems_report = {
        name: evaluate_system(
            name,
            validation,
            generator,
            metadata=metadata[name],
            leakage_clean=clean,
            failure_limit=args.failures,
        )
        for name, generator in generators.items()
    }

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": {
            "path": str(args.dataset),
            "train_cases": len(dataset.train),
            "validation_cases": len(validation),
            "seed": dataset.seed,
            "provenance": dataset.provenance,
            "limitations": dataset.limitations,
        },
        "leakage": leakage,
        "systems": systems_report,
    }

    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(_comparison_table(report))

    if args.save:
        run_dir = ensure_dir(
            _resolve(args.save) / f"generation_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        )
        write_json(run_dir / "report.json", report)
        (run_dir / "report.md").write_text(_markdown(report), encoding="utf-8")
        _write_csv(run_dir / "per_case.csv", report)
        (run_dir / "leakage.json").write_text(json.dumps(leakage, indent=2), encoding="utf-8")
        print(f"report written under: {run_dir}")
    return 0


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


if __name__ == "__main__":
    raise SystemExit(main())
