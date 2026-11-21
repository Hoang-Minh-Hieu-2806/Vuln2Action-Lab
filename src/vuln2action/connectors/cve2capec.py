"""Read the external CVE2CAPEC reference database (evaluation only).

The upstream repository stores one gzip-compressed JSONL file per CVE year.
Each line is an object keyed by a CVE id and contains ``CWE``/``CAPEC`` id
lists. This loader only reads local files; it never performs network access.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from vuln2action.domain import CveCapecReference


def _iter_lines(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else Path.open
    mode = "rt" if path.suffix == ".gz" else "r"
    kwargs = (
        {"encoding": "utf-8", "errors": "replace"}
        if path.suffix == ".gz"
        else {"encoding": "utf-8"}
    )
    with opener(path, mode, **kwargs) as handle:  # type: ignore[arg-type]
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield stripped


def _normalise(value: Any, prefix: str) -> str:
    text = str(value).strip().upper()
    if not text:
        return ""
    if text.startswith(prefix):
        return text
    return f"{prefix}-{text}"


def _iter_paths(source: str | Path | Iterable[str | Path]) -> Iterator[Path]:
    if isinstance(source, (str, Path)):
        path = Path(source)
        if path.is_dir():
            yield from sorted(path.glob("CVE-*.jsonl.gz"))
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(f"CVE2CAPEC path not found: {path}")
        return
    for item in source:
        path = Path(item)
        if path.is_dir():
            yield from sorted(path.glob("CVE-*.jsonl.gz"))
        elif path.is_file():
            yield path


def load_cve2capec(
    source: str | Path | Iterable[str | Path],
    cve_ids: set[str] | None = None,
) -> dict[str, CveCapecReference]:
    """Load CVE2CAPEC mapping, optionally restricted to ``cve_ids``."""
    wanted = {cve.upper() for cve in cve_ids} if cve_ids is not None else None
    mapping: dict[str, CveCapecReference] = {}
    for path in _iter_paths(source):
        for line in _iter_lines(path):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            for raw_cve_id, raw_values in payload.items():
                cve_id = str(raw_cve_id).strip().upper()
                if not cve_id.startswith("CVE-"):
                    continue
                if wanted is not None and cve_id not in wanted:
                    continue
                if not isinstance(raw_values, dict):
                    continue
                cwe_ids = [
                    value
                    for item in raw_values.get("CWE") or []
                    if (value := _normalise(item, "CWE"))
                ]
                capec_ids = [
                    value
                    for item in raw_values.get("CAPEC") or []
                    if (value := _normalise(item, "CAPEC"))
                ]
                mapping[cve_id] = CveCapecReference(
                    cve_id=cve_id,
                    cwe_ids=sorted(set(cwe_ids)),
                    capec_ids=sorted(set(capec_ids)),
                )
    return mapping
