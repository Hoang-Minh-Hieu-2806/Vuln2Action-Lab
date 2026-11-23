"""Persist a report in a run-specific directory."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from vuln2action.evidence.provenance import ProvenanceError, build_provenance, write_provenance
from vuln2action.utils.filesystem import ensure_dir, repo_path, write_json


class ReportPaths(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_dir: str
    json_path: str
    markdown_path: str


def _md_inline(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace("`", "\\`")
    text = text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _safe_run_id(run_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id.strip()).strip(".-")
    if not safe:
        raise ValueError("run_id must contain at least one safe character")
    return safe


def save_report(
    run_id: str,
    payload: dict[str, Any],
    output_dir: str | Path = "results",
    *,
    overwrite: bool = False,
) -> ReportPaths:
    root = Path(output_dir)
    if not root.is_absolute():
        root = repo_path(str(root))
    run_dir = root / _safe_run_id(run_id)
    if (run_dir / "report.json").exists() and not overwrite:
        raise FileExistsError(
            f"Report already exists at {run_dir / 'report.json'}; "
            "choose a new run id or pass overwrite=True explicitly"
        )
    ensure_dir(run_dir)
    try:
        sidecar = write_provenance(run_dir, build_provenance(payload))
    except Exception as exc:
        raise ProvenanceError(
            "WRITE_FAILED",
            f"Provenance sidecar write failed; report not published: {exc}",
        ) from exc
    published = copy.deepcopy(payload)
    evidence = published.get("evidence")
    if isinstance(evidence, dict):
        generation = evidence.get("generation")
        if not isinstance(generation, dict):
            generation = {}
            evidence["generation"] = generation
        generation["provenance_ref"] = sidecar.name
    try:
        json_path = write_json(run_dir / "report.json", published)
    except Exception as exc:
        raise RuntimeError(
            f"Report write failed after sidecar {sidecar.name} was written "
            f"(orphan sidecar kept): {exc}"
        ) from exc
    markdown_path = run_dir / "report.md"
    result = published.get("result", {})
    markdown_path.write_text(
        f"# Vuln2Action-Lab run: {_md_inline(run_id)}\n\n"
        f"- Vulnerability: {_md_inline(payload.get('cve_id', '?'))}\n"
        f"- Provider: {_md_inline(payload.get('provider', '?'))}\n"
        f"- Verdict: **{_md_inline(result.get('status', 'UNKNOWN'))}**\n\n"
        "The JSON report contains the complete typed evidence bundle.\n",
        encoding="utf-8",
    )
    return ReportPaths(
        run_dir=str(run_dir),
        json_path=str(json_path),
        markdown_path=str(markdown_path),
    )
