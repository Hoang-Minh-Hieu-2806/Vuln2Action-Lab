"""Local Flask GUI for CVE -> CAPEC -> execution flow inspection.

The GUI is read-only: it loads local dataset tables, runs lexical/semantic
selection, and displays CAPEC/ExploitDB descriptions. It never executes exploit
code. Bind it to 127.0.0.1 only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from flask import Flask, jsonify, render_template, request

from vuln2action.generation.flow_dataset import PHASES, phase_steps
from vuln2action.mapping import (
    TfidfCapecSelector,
    load_selection_dataset,
)


def _load_predictions(path: Path) -> dict[str, dict[str, Any]]:
    predictions: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return predictions
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("selected_capec_id"):
                predictions[row["cve_id"]] = row
    return predictions


def _load_technique_map(path: Path) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return mapping
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            mapping[row["technique"]] = row
    return mapping


def _flow_view(capec: Any, technique_map: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    grouped = phase_steps(capec)
    view: list[dict[str, Any]] = []
    for phase in PHASES:
        steps: list[dict[str, Any]] = []
        for step in grouped[phase]:
            techniques = []
            for technique in step.techniques:
                match = technique_map.get(technique)
                techniques.append(
                    {
                        "text": technique,
                        "exploit_id": match.get("exploit_id", "") if match else "",
                        "exploit_description": match.get("description", "") if match else "",
                        "score": match.get("score", 0.0) if match else 0.0,
                    }
                )
            steps.append(
                {
                    "step": step.step,
                    "description": step.description,
                    "techniques": techniques,
                }
            )
        view.append({"phase": phase, "steps": steps})
    return view


def create_app(
    dataset_dir: str | Path = "data/processed/reproduction",
    predictions_path: str | Path | None = None,
    technique_map_path: str | Path | None = None,
) -> Flask:
    root = Path(dataset_dir)
    dataset = load_selection_dataset(root)
    predictions_file = (
        Path(predictions_path)
        if predictions_path is not None
        else root / "capec_selection" / "capec_predictions_word2vec_all.jsonl"
    )
    technique_file = (
        Path(technique_map_path)
        if technique_map_path is not None
        else root / "flow_dataset_stage2" / "technique_exploit_map.jsonl"
    )
    predictions = _load_predictions(predictions_file)
    technique_map = _load_technique_map(technique_file)
    fallback_selector = TfidfCapecSelector(dataset.capecs)

    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["DATASET_DIR"] = str(root)
    app.config["PREDICTIONS_FILE"] = str(predictions_file)
    app.config["TECHNIQUE_MAP_FILE"] = str(technique_file)

    def analyze(cve_id: str, description: str) -> dict[str, Any]:
        cve = dataset.cves.get(cve_id)
        if cve_id and cve is None:
            return {"error": f"unknown CVE in the local 55k dataset: {cve_id}"}
        if cve is not None:
            description = cve.description
        if not description.strip():
            return {"error": "provide a CVE id or a vulnerability description"}
        candidate_ids = dataset.candidates.get(cve_id, ()) if cve_id else ()
        method = "TF-IDF"
        selected_id = None
        score = 0.0
        if cve_id and cve_id in predictions:
            selected_id = predictions[cve_id]["selected_capec_id"]
            score = float(predictions[cve_id].get("score", 0.0))
            method = "precomputed Word2Vec"
        elif candidate_ids:
            selected_id, score = fallback_selector.select(description, candidate_ids)
        else:
            selected_id, score = fallback_selector.select(description, dataset.capecs)
            method = "TF-IDF over all CAPECs"
        capec = dataset.capecs.get(selected_id) if selected_id else None
        if capec is None:
            return {"error": "no CAPEC could be selected for this input"}
        candidate_details = []
        for candidate_id in sorted(candidate_ids or dataset.capecs)[:12]:
            candidate = dataset.capecs.get(candidate_id)
            if candidate is not None:
                candidate_details.append({"capec_id": candidate_id, "name": candidate.name})
        return {
            "cve_id": cve_id or "(description input)",
            "description": description,
            "method": method,
            "selected_capec_id": capec.capec_id,
            "selected_capec_name": capec.name,
            "selected_capec_description": capec.description,
            "score": score,
            "flow": _flow_view(capec, technique_map),
            "candidates": candidate_details,
            "has_technique_mapping": bool(technique_map),
        }

    @app.get("/")
    def index() -> str:
        examples = sorted(dataset.splits.get("train", []))[:8]
        return render_template("index.html", result=None, error="", examples=examples)

    @app.post("/analyze")
    def analyze_form() -> str:
        cve_id = request.form.get("cve_id", "").strip().upper()
        description = request.form.get("description", "").strip()
        result = analyze(cve_id, description)
        examples = sorted(dataset.splits.get("train", []))[:8]
        return render_template(
            "index.html",
            result=result,
            error=result.get("error", ""),
            examples=examples,
        )

    @app.get("/api/analyze")
    def analyze_api() -> tuple[Any, int]:
        cve_id = request.args.get("cve_id", "").strip().upper()
        description = request.args.get("description", "").strip()
        result = analyze(cve_id, description)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.get("/health")
    def health() -> tuple[Any, int]:
        return jsonify(
            {
                "status": "ok",
                "dataset": str(root),
                "cves": len(dataset.cves),
                "capecs": len(dataset.capecs),
                "predictions": len(predictions),
                "technique_mappings": len(technique_map),
            }
        ), 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)
