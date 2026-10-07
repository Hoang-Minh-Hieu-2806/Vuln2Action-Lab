"""Report writer: persist JSON + Markdown reports under results/."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.utils.filesystem import ensure_dir, write_json


@dataclass
class ReportPaths:
    json_path: str
    markdown_path: str


def save_report(run_id: str, payload: dict[str, Any], output_dir: str | Path = "results") -> ReportPaths:
    """Write payload as JSON + a short Markdown summary. Returns paths."""
    out = ensure_dir(output_dir)
    json_path = write_json(out / f"{run_id}.json", payload)
    md_path = out / f"{run_id}.md"
    status = payload.get("result", {}).get("status", "UNKNOWN")
    md_path.write_text(
        f"# Vuln2Action-Lab run: {run_id}\n\n"
        f"- CVE: {payload.get('cve_id', '?')}\n"
        f"- Provider: {payload.get('provider', '?')}\n"
        f"- Verdict: **{status}**\n\n"
        "See the JSON report for full evidence.\n",
        encoding="utf-8",
    )
    return ReportPaths(json_path=str(json_path), markdown_path=str(md_path))
