"""Build the T5 training set from MITRE CAPEC execution flows.

Provenance
----------
Every target sequence comes verbatim from the MITRE CAPEC catalog's
``Execution_Flow`` element. Each ``Attack_Step`` carries an analyst-assigned
``Phase`` of ``Explore``, ``Experiment`` or ``Exploit`` plus a ``Step`` number and
a description. That is the only ground truth used here: we re-order and
re-format MITRE's own text into the paper's three-stage shape and never invent a
step, a technique or an exploit.

What this dataset is **not**
---------------------------
These are *textual procedural abstractions* of attack patterns, not validated
reproduction steps for a specific CVE. A CAPEC pattern is a class of attack;
mapping a pattern onto a concrete CVE still requires the CVE's own context. The
model therefore learns "how a pattern of this kind is described", not "what to
run against product X".

Inputs are built from the CAPEC pattern's name, description, its related CWEs and
its known CVE examples when MITRE lists any. No CVE text is fetched here, so the
builder stays offline once ``--source`` (the CAPEC XML) is present.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.utils.filesystem import ensure_dir, write_json

RAW_CAPEC = ("data", "raw", "capec", "capec_latest.xml")
OUTPUT = ("data", "processed", "t5_flows.json")
PHASES = ("Explore", "Experiment", "Exploit")
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
_CLEAN = re.compile(r"\s+")

TASK_PREFIX = "Generate the Explore/Experiment/Exploit attack flow for this weakness: "


class MissingSourceError(RuntimeError):
    """Raised when the CAPEC snapshot has not been downloaded."""


def _safe_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def _xml_root(path: Path) -> ElementTree.Element:
    if not path.is_file():
        raise MissingSourceError(
            f"CAPEC catalog not found: {path}. Run: python scripts/download_data.py --source capec"
        )
    root = ElementTree.fromstring(path.read_bytes())
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


def _clean(text: str | None) -> str:
    return _CLEAN.sub(" ", (text or "")).strip()


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def parse_capec_flows(path: Path | None = None) -> list[dict[str, Any]]:
    """Extract ``{pattern, input_text, target_flow, steps}`` records.

    A pattern is kept only when its execution flow contains at least one step in
    each of the three phases, so the target always has the Explore → Experiment
    → Exploit shape the pipeline emits. Steps keep MITRE's own ordering and text.
    """
    snapshot = Path(path) if path is not None else project_root().joinpath(*RAW_CAPEC)
    root = _xml_root(snapshot)
    records: list[dict[str, Any]] = []

    for attack in root.iter("Attack_Pattern"):
        flow = attack.find("Execution_Flow")
        if flow is None:
            continue
        steps: list[dict[str, Any]] = []
        for step in flow.findall("Attack_Step"):
            phase = _clean(step.findtext("Phase"))
            if phase not in PHASES:
                continue
            description = _clean(step.findtext("Description"))
            if not description:
                continue
            techniques = [
                _clean(item.text) for item in step.findall(".//Technique") if _clean(item.text)
            ]
            steps.append(
                {
                    "step": _clean(step.findtext("Step")) or str(len(steps) + 1),
                    "phase": phase,
                    "description": description,
                    "techniques": techniques,
                }
            )
        present = {step["phase"] for step in steps}
        if present != set(PHASES):
            continue
        steps.sort(key=lambda item: (_PHASE_ORDER[item["phase"]], _step_key(item["step"])))

        capec_id = f"CAPEC-{attack.get('ID')}"
        name = _clean(attack.get("Name"))
        description = _clean(attack.findtext("Description"))
        cwes = sorted(
            {
                f"CWE-{(relation.get('CWE_ID') or '').strip()}"
                for relation in attack.findall(".//Related_Weakness")
                if (relation.get("CWE_ID") or "").strip()
            }
        )
        examples = sorted(
            set(_CVE_PATTERN.findall(" ".join(attack.find("Example_Instances").itertext())))
            if attack.find("Example_Instances") is not None
            else set()
        )

        records.append(
            {
                "capec_id": capec_id,
                "name": name,
                "cwe_ids": cwes,
                "cve_ids": examples,
                "input_text": build_input(capec_id, name, description, cwes, examples),
                "target_flow": build_target(capec_id, name, steps),
                "steps": steps,
            }
        )
    return sorted(records, key=lambda item: _capid_key(item["capec_id"]))


_PHASE_ORDER = {phase: index for index, phase in enumerate(PHASES)}


def _step_key(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _capid_key(value: str) -> int:
    digits = "".join(char for char in value if char.isdigit())
    return int(digits) if digits else 0


def build_input(
    capec_id: str,
    name: str,
    description: str,
    cwes: list[str],
    cves: list[str],
) -> str:
    """Deterministic model input; the task prefix matches inference time."""
    parts = [TASK_PREFIX, f"{capec_id} {name}."]
    if description:
        parts.append(description)
    if cwes:
        parts.append("Weaknesses: " + ", ".join(cwes) + ".")
    if cves:
        parts.append("Known examples: " + ", ".join(cves) + ".")
    return " ".join(parts)


def build_target(capec_id: str, name: str, steps: list[dict[str, Any]]) -> str:
    """Render the three-stage flow that the model is trained to emit."""
    lines = [f"{capec_id} {name}"]
    for index, step in enumerate(steps, start=1):
        lines.append(f"{index}. {step['phase']}: {step['description']}")
        for technique in step["techniques"]:
            lines.append(f"   - {technique}")
    return "\n".join(lines)


def split_records(
    records: list[dict[str, Any]],
    *,
    validation_fraction: float = 0.15,
    seed: int = 13,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic hash-based split (stable across Python versions/machines)."""
    if not 0.0 <= validation_fraction < 1.0:
        raise ValueError("validation_fraction must be in [0, 1)")

    def bucket(record: dict[str, Any]) -> float:
        digest = hashlib.sha256(f"{seed}:{record['capec_id']}".encode()).hexdigest()
        return int(digest[:8], 16) / 0xFFFFFFFF

    train = [record for record in records if bucket(record) >= validation_fraction]
    validation = [record for record in records if bucket(record) < validation_fraction]
    if not validation and validation_fraction > 0 and len(train) > 1:
        # Guarantee a usable validation slice for tiny catalogs/fixtures.
        train, validation = train[:-1], [train[-1]]
    return train, validation


def build_payload(
    train: list[dict[str, Any]],
    validation: list[dict[str, Any]],
    *,
    source_path: Path,
    seed: int,
    validation_fraction: float,
) -> dict[str, Any]:
    all_records = train + validation
    phase_counts: dict[str, int] = {phase: 0 for phase in PHASES}
    for record in all_records:
        for step in record["steps"]:
            phase_counts[step["phase"]] += 1
    return {
        "version": "1.0.0",
        "description": (
            "CVE/CWE/CAPEC description -> Explore/Experiment/Exploit flow, "
            "derived verbatim from MITRE CAPEC Execution_Flow phases."
        ),
        "provenance": {
            "source": str(source_path),
            "source_kind": "MITRE CAPEC catalog Execution_Flow",
            "label_origin": (
                "Each Attack_Step's analyst-assigned Phase (Explore|Experiment|Exploit) "
                "and description text, copied without edits."
            ),
            "ground_truth_claim": (
                "Attack-pattern level only. These are textual procedural abstractions, "
                "not validated reproduction steps for any specific CVE."
            ),
        },
        "limitations": [
            "Only CAPEC patterns that declare steps in all three phases are included.",
            (
                "A CAPEC pattern is an attack class, not a concrete CVE; CVE-specific "
                "preconditions are absent unless MITRE listed example CVEs."
            ),
            "Steps are guidance text, never executable exploits.",
            "Coverage is limited to MITRE-authored flows (239 of 615 patterns).",
        ],
        "built_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "validation_fraction": validation_fraction,
        "task_prefix": TASK_PREFIX,
        "phase_step_counts": phase_counts,
        "record_count": len(all_records),
        "train_count": len(train),
        "validation_count": len(validation),
        "train": train,
        "validation": validation,
    }


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(
        description="Build the T5 flow dataset from the MITRE CAPEC catalog."
    )
    parser.add_argument("--source", default=str(Path(*RAW_CAPEC)), help="CAPEC XML snapshot.")
    parser.add_argument("--out", default=str(Path(*OUTPUT)), help="Output JSON path.")
    parser.add_argument("--seed", type=int, default=13, help="Split seed (default: 13).")
    parser.add_argument(
        "--validation-fraction",
        type=float,
        default=0.15,
        help="Fraction held out for validation (default: 0.15).",
    )
    args = parser.parse_args(argv)
    if not 0.0 <= args.validation_fraction < 1.0:
        parser.error("--validation-fraction must be in [0, 1)")

    source = _resolve(args.source)
    try:
        records = parse_capec_flows(source)
    except (MissingSourceError, ElementTree.ParseError) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    if not records:
        parser.error("no CAPEC pattern declared steps in all three phases")
    train, validation = split_records(
        records, validation_fraction=args.validation_fraction, seed=args.seed
    )
    payload = build_payload(
        train,
        validation,
        source_path=source,
        seed=args.seed,
        validation_fraction=args.validation_fraction,
    )
    out_path = write_json(_resolve(args.out), payload)
    ensure_dir(_resolve(args.out).parent)

    print(f"wrote {payload['record_count']} flows -> {out_path}")
    print(
        f"train={payload['train_count']} validation={payload['validation_count']} "
        f"steps={payload['phase_step_counts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
