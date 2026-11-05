"""Validate the generated paper-reproduction dataset.

This is a local, read-only consistency check. It does not download anything.

    python scripts/audit_reproduction_dataset.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.utils.filesystem import read_json, read_jsonl


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _duplicates(values: list[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def audit(dataset_dir: str | Path) -> dict[str, Any]:
    root = _resolve(dataset_dir)
    errors: list[str] = []
    warnings: list[str] = []

    required = [
        "cves.jsonl",
        "cwe.json",
        "capec.json",
        "cve_cwe.jsonl",
        "cwe_capec.jsonl",
        "cve_capec_candidates.jsonl",
        "cve2capec_reference.jsonl",
        "exploitdb.jsonl",
        "splits.json",
        "stats.json",
    ]
    missing = [name for name in required if not (root / name).exists()]
    if missing:
        return {"ok": False, "errors": [f"missing output: {name}" for name in missing]}

    cves = read_jsonl(root / "cves.jsonl")
    cwes = read_json(root / "cwe.json")
    capecs = read_json(root / "capec.json")
    cve_cwe = read_jsonl(root / "cve_cwe.jsonl")
    cwe_capec = read_jsonl(root / "cwe_capec.jsonl")
    candidates = read_jsonl(root / "cve_capec_candidates.jsonl")
    references = read_jsonl(root / "cve2capec_reference.jsonl")
    exploits = read_jsonl(root / "exploitdb.jsonl")
    splits = read_json(root / "splits.json")
    stats = read_json(root / "stats.json")

    cve_ids = [str(row.get("cve_id", "")) for row in cves]
    cwe_ids = {str(row.get("cwe_id", "")) for row in cwes}
    capec_ids = {str(row.get("capec_id", "")) for row in capecs}
    cve_id_set = set(cve_ids)
    if "" in cve_id_set:
        errors.append("cves.jsonl contains an empty cve_id")
    if duplicates := _duplicates(cve_ids):
        errors.append(f"duplicate CVE ids: {duplicates[:5]}")
    if duplicates := _duplicates([str(row.get("cwe_id", "")) for row in cwes]):
        errors.append(f"duplicate CWE ids: {duplicates[:5]}")
    if duplicates := _duplicates([str(row.get("capec_id", "")) for row in capecs]):
        errors.append(f"duplicate CAPEC ids: {duplicates[:5]}")

    missing_cwe = Counter(
        str(row.get("cwe_id", "")) for row in cve_cwe if row.get("cwe_id") not in cwe_ids
    )
    for row in cve_cwe:
        if row.get("cve_id") not in cve_id_set:
            errors.append(f"CVE-CWE row references unknown CVE: {row.get('cve_id')}")
            break

    if missing_cwe:
        summary = ", ".join(f"{cwe_id}={count}" for cwe_id, count in missing_cwe.most_common(10))
        warnings.append(
            f"{sum(missing_cwe.values())} CVE-CWE rows use CWEs absent from the current "
            f"catalog (deprecated NVD labels): {summary}"
        )

    for row in cwe_capec:
        if row.get("cwe_id") not in cwe_ids:
            errors.append(f"CWE-CAPEC row references unknown CWE: {row.get('cwe_id')}")
            break
        if row.get("capec_id") not in capec_ids:
            errors.append(f"CWE-CAPEC row references unknown CAPEC: {row.get('capec_id')}")
            break

    missing_candidate_cwe = Counter(
        str(row.get("cwe_id", "")) for row in candidates if row.get("cwe_id") not in cwe_ids
    )
    if missing_candidate_cwe:
        summary = ", ".join(
            f"{cwe_id}={count}" for cwe_id, count in missing_candidate_cwe.most_common(10)
        )
        warnings.append(
            f"{sum(missing_candidate_cwe.values())} candidate rows use CWEs absent from the "
            f"current catalog: {summary}"
        )
    for row in candidates:
        if row.get("cve_id") not in cve_id_set:
            errors.append(f"candidate row references unknown CVE: {row.get('cve_id')}")
            break
        for capec_id in row.get("candidate_capec_ids") or []:
            if capec_id not in capec_ids:
                errors.append(f"candidate row references unknown CAPEC: {capec_id}")
                break

    for row in references:
        if row.get("cve_id") not in cve_id_set:
            errors.append(f"CVE2CAPEC row references unselected CVE: {row.get('cve_id')}")
            break

    split_names = ("train", "validation", "capec_eval_100", "human_eval_20")
    missing_splits = [name for name in split_names if name not in splits]
    if missing_splits:
        errors.append(f"splits.json missing keys: {missing_splits}")
    else:
        split_sets = {name: set(splits[name]) for name in split_names}
        for name, values in split_sets.items():
            unknown = values - cve_id_set
            if unknown:
                errors.append(f"{name} contains unknown CVE: {min(unknown)}")
        names = list(split_sets)
        for index, left in enumerate(names):
            for right in names[index + 1 :]:
                overlap = split_sets[left] & split_sets[right]
                if overlap:
                    errors.append(f"split overlap {left}/{right}: {min(overlap)}")
        union = set().union(*split_sets.values())
        if union != cve_id_set:
            warnings.append(
                f"split union differs from selected CVEs: missing={len(cve_id_set - union)}, "
                f"extra={len(union - cve_id_set)}"
            )

    expected_counts = {
        "selected_cves": len(cves),
        "cve_cwe_pairs": len(cve_cwe),
        "cwe_capec_pairs": len(cwe_capec),
        "candidate_rows": len(candidates),
        "cve2capec_reference_rows": len(references),
        "exploit_rows_total": len(exploits),
    }
    for key, actual in expected_counts.items():
        if stats.get(key) != actual:
            errors.append(f"stats.{key}={stats.get(key)} but file count={actual}")

    if stats.get("raw_cves_total", 0) >= stats.get("target_cves", 0) and stats.get(
        "selected_cves"
    ) != stats.get("target_cves"):
        errors.append(
            f"selected_cves={stats.get('selected_cves')} does not match "
            f"target_cves={stats.get('target_cves')}"
        )
    forbidden = {"content", "code", "source_code", "exploit_code"}
    for row in exploits:
        if forbidden & set(row):
            errors.append(
                f"exploitdb row contains forbidden source-code field: {sorted(forbidden & set(row))}"
            )
            break

    if not cves:
        errors.append("cves.jsonl is empty")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "counts": {
            "cves": len(cves),
            "cwe": len(cwes),
            "capec": len(capecs),
            "cve_cwe": len(cve_cwe),
            "cwe_capec": len(cwe_capec),
            "candidate_rows": len(candidates),
            "cve2capec_reference_rows": len(references),
            "exploit_rows": len(exploits),
            "splits": {name: len(splits.get(name, [])) for name in split_names},
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a reproduction dataset directory.")
    parser.add_argument("--dataset", default="data/processed/reproduction")
    args = parser.parse_args(argv)
    report = audit(args.dataset)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
