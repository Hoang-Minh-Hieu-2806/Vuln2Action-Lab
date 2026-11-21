"""Deterministic dataset construction for the paper reproduction.

This module only reads local snapshots. It builds the relational tables needed
by the CVE -> CWE -> CAPEC stage and the later generation stage:

* CVE records sampled across NVD annual feeds
* CWE/CAPEC catalog records with relations and execution flows
* CVE-CWE and CWE-CAPEC pair tables
* CVE-CAPEC candidate rows
* CVE2CAPEC evaluation references
* ExploitDB metadata rows

No exploit source code is downloaded or written here.
"""

from __future__ import annotations

import gzip
import json
import random
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from vuln2action.connectors.mitre import parse_capec_xml, parse_cwe_xml
from vuln2action.connectors.nvd import parse_nvd_records
from vuln2action.domain import CapecRecord, CveCapecReference, CveRecord, CweRecord, ExploitRecord

_FEED_YEAR = re.compile(r"nvdcve-2\.0-(\d{4})\.json\.gz$")

# The 20 CVEs used for the paper's human study. The final list is filled with
# deterministic samples when a CVE is outside the selected cutoff.
PAPER_HUMAN_EVAL_CVES = [
    "CVE-2020-1472",
    "CVE-2020-0796",
    "CVE-2020-35848",
    "CVE-2020-25079",
    "CVE-2020-25078",
    "CVE-2020-14060",
    "CVE-2021-44228",
    "CVE-2021-26855",
    "CVE-2021-21972",
    "CVE-2022-22536",
    "CVE-2022-22965",
    "CVE-2022-26134",
    "CVE-2022-30190",
    "CVE-2021-36942",
    "CVE-2023-28252",
    "CVE-2023-43643",
    "CVE-2024-9463",
    "CVE-2024-5910",
    "CVE-2024-41713",
    "CVE-2024-55550",
]


def _open_text(path: str | Path):
    resolved = Path(path)
    if resolved.suffix == ".gz":
        return gzip.open(resolved, "rt", encoding="utf-8", errors="replace")
    return resolved.open(encoding="utf-8", errors="replace")


def load_nvd_feed(path: str | Path) -> list[CveRecord]:
    """Load one NVD 2.0 annual feed and normalise non-rejected CVEs."""
    with _open_text(path) as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise TypeError(f"NVD feed is not a JSON object: {path}")
    return parse_nvd_records(payload, skip_invalid=True)


def load_nvd_feeds(
    feed_dir: str | Path,
    start_year: int | None = None,
    end_year: int | None = None,
) -> dict[int, list[CveRecord]]:
    """Load annual NVD feeds keyed by year."""
    records_by_year: dict[int, list[CveRecord]] = {}
    for path in sorted(Path(feed_dir).glob("nvdcve-2.0-*.json.gz")):
        match = _FEED_YEAR.search(path.name)
        if not match:
            continue
        year = int(match.group(1))
        if start_year is not None and year < start_year:
            continue
        if end_year is not None and year > end_year:
            continue
        records_by_year[year] = load_nvd_feed(path)
    return records_by_year


def allocate_quotas(counts: Mapping[int, int], target: int) -> dict[int, int]:
    """Allocate a target sample size proportionally using largest remainders."""
    total = sum(counts.values())
    if target <= 0 or total == 0:
        return {year: 0 for year in counts}
    if target >= total:
        return dict(counts)
    exact = {year: count * target / total for year, count in counts.items()}
    quotas = {year: int(value) for year, value in exact.items()}
    remaining = target - sum(quotas.values())
    order = sorted(
        counts,
        key=lambda year: (exact[year] - quotas[year], counts[year], year),
        reverse=True,
    )
    for year in order[:remaining]:
        quotas[year] += 1
    return quotas


def sample_records_by_year(
    records_by_year: Mapping[int, list[CveRecord]],
    target: int,
    seed: int = 42,
) -> list[CveRecord]:
    """Take a deterministic, year-stratified sample across NVD feeds."""
    counts = {year: len(records) for year, records in records_by_year.items()}
    quotas = allocate_quotas(counts, target)
    selected: list[CveRecord] = []
    for year in sorted(records_by_year):
        records = records_by_year[year]
        quota = min(quotas.get(year, 0), len(records))
        if quota <= 0:
            continue
        rng = random.Random(seed + year)
        selected.extend(rng.sample(records, quota))
    selected.sort(key=lambda record: record.cve_id)
    return selected


def select_newest_records(
    records_by_year: Mapping[int, list[CveRecord]],
    target: int,
) -> list[CveRecord]:
    """Select the newest CVEs by NVD published timestamp, newest first."""
    if target <= 0:
        return []
    records = [record for year in sorted(records_by_year) for record in records_by_year[year]]
    records.sort(
        key=lambda record: (record.published or "", record.cve_id),
        reverse=True,
    )
    return records[:target]


def build_cve_cwe_pairs(
    records: Iterable[CveRecord],
    known_cwe_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        for cwe_id in record.cwe:
            key = (record.cve_id, cwe_id)
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {"cve_id": record.cve_id, "cwe_id": cwe_id}
            if known_cwe_ids is not None:
                row["cwe_in_catalog"] = cwe_id in known_cwe_ids
            pairs.append(row)
    return pairs


def build_cwe_capec_pairs(
    cwes: Iterable[CweRecord],
    capecs: Iterable[CapecRecord],
) -> list[dict[str, str]]:
    capec_ids = {record.capec_id for record in capecs}
    cwe_ids = {record.cwe_id for record in cwes}
    pairs: set[tuple[str, str]] = set()
    for record in cwes:
        for capec_id in record.related_capec_ids:
            if capec_id in capec_ids:
                pairs.add((record.cwe_id, capec_id))
    for record in capecs:
        for cwe_id in record.related_cwe_ids:
            if cwe_id in cwe_ids:
                pairs.add((cwe_id, record.capec_id))
    return [{"cwe_id": cwe_id, "capec_id": capec_id} for cwe_id, capec_id in sorted(pairs)]


def build_candidate_rows(
    records: Iterable[CveRecord],
    cwe_capec_pairs: Iterable[dict[str, str]],
    known_cwe_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    by_cwe: dict[str, list[str]] = defaultdict(list)
    for pair in cwe_capec_pairs:
        by_cwe[pair["cwe_id"]].append(pair["capec_id"])
    rows: list[dict[str, Any]] = []
    for record in records:
        for cwe_id in record.cwe:
            candidates = sorted(set(by_cwe.get(cwe_id, [])))
            row: dict[str, Any] = {
                "cve_id": record.cve_id,
                "cwe_id": cwe_id,
                "candidate_capec_ids": candidates,
                "candidate_source": "cwe_capec",
            }
            if known_cwe_ids is not None:
                row["cwe_in_catalog"] = cwe_id in known_cwe_ids
            rows.append(row)
    return rows


def build_reference_rows(mapping: Mapping[str, CveCapecReference]) -> list[dict[str, Any]]:
    return [mapping[cve_id].model_dump(mode="json") for cve_id in sorted(mapping)]


def make_splits(
    cve_ids: Iterable[str],
    reference_ids: Iterable[str],
    seed: int = 42,
    capec_eval_size: int = 100,
    human_eval_size: int = 20,
) -> dict[str, list[str]]:
    """Create leakage-free splits, reserving CAPEC and human evaluation sets."""
    all_ids = sorted(set(cve_ids))
    known = set(all_ids)
    rng = random.Random(seed)

    human: list[str] = [cve_id for cve_id in PAPER_HUMAN_EVAL_CVES if cve_id in known]
    if len(human) < human_eval_size:
        pool = [cve_id for cve_id in all_ids if cve_id not in set(human)]
        human.extend(rng.sample(pool, min(human_eval_size - len(human), len(pool))))
    human = sorted(human[:human_eval_size])
    human_set = set(human)

    reference_pool = sorted((set(reference_ids) & known) - human_set)
    capec_eval = rng.sample(reference_pool, min(capec_eval_size, len(reference_pool)))
    if len(capec_eval) < capec_eval_size:
        pool = [cve_id for cve_id in all_ids if cve_id not in human_set | set(capec_eval)]
        capec_eval.extend(rng.sample(pool, min(capec_eval_size - len(capec_eval), len(pool))))
    capec_eval = sorted(capec_eval[:capec_eval_size])
    eval_set = human_set | set(capec_eval)

    remaining = [cve_id for cve_id in all_ids if cve_id not in eval_set]
    rng.shuffle(remaining)
    split_at = int(len(remaining) * 0.8)
    return {
        "train": sorted(remaining[:split_at]),
        "validation": sorted(remaining[split_at:]),
        "capec_eval_100": capec_eval,
        "human_eval_20": human,
    }


def catalog_metadata(path: str | Path) -> dict[str, str]:
    root = ElementTree.parse(path).getroot()
    return {
        "name": root.get("Name", ""),
        "version": root.get("Version", ""),
        "date": root.get("Date", ""),
    }


def parse_catalogs(
    cwe_path: str | Path,
    capec_path: str | Path,
) -> tuple[list[CweRecord], list[CapecRecord]]:
    return parse_cwe_xml(cwe_path), parse_capec_xml(capec_path)


def exploit_rows_for_selected(
    exploits: Iterable[ExploitRecord],
    cve_ids: set[str],
) -> list[dict[str, Any]]:
    """Keep all exploit descriptions but restrict each row's CVE list to the sample."""
    rows: list[dict[str, Any]] = []
    for exploit in exploits:
        selected = sorted(set(exploit.cve_ids) & cve_ids)
        rows.append({**exploit.model_dump(mode="json"), "cve_ids": selected})
    return rows


def dataset_stats(
    *,
    records_by_year: Mapping[int, list[CveRecord]],
    selected: list[CveRecord],
    cwes: list[CweRecord],
    capecs: list[CapecRecord],
    cve_cwe_pairs: list[dict[str, Any]],
    cwe_capec_pairs: list[dict[str, str]],
    candidate_rows: list[dict[str, Any]],
    references: Mapping[str, CveCapecReference],
    exploits: list[ExploitRecord],
    exploit_rows: list[dict[str, Any]],
    splits: Mapping[str, list[str]],
    target: int,
    seed: int,
    selection_strategy: str,
    cwe_meta: Mapping[str, str],
    capec_meta: Mapping[str, str],
) -> dict[str, Any]:
    selected_ids = {record.cve_id for record in selected}
    selected_by_year: dict[str, int] = defaultdict(int)
    for record in selected:
        match = re.match(r"CVE-(\d{4})-", record.cve_id)
        selected_by_year[match.group(1) if match else "unknown"] += 1
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "paper_cve_count": 114_560,
        "target_cves": target,
        "seed": seed,
        "selection_strategy": selection_strategy,
        "raw_cves_by_year": {
            str(year): len(records) for year, records in sorted(records_by_year.items())
        },
        "raw_cves_total": sum(len(records) for records in records_by_year.values()),
        "selected_cves": len(selected),
        "selected_cves_by_year": dict(sorted(selected_by_year.items())),
        "selected_cves_with_cwe": sum(1 for record in selected if record.cwe),
        "selected_cves_with_cvss": sum(1 for record in selected if record.cvss is not None),
        "selected_cves_with_cpe": sum(1 for record in selected if record.cpe),
        "cwe_count": len(cwes),
        "capec_count": len(capecs),
        "cwe_with_relations": sum(
            1 for record in cwes if record.parent_ids or record.related_capec_ids
        ),
        "capec_with_execution_flow": sum(1 for record in capecs if record.execution_flow),
        "cve_cwe_pairs": len(cve_cwe_pairs),
        "cve_cwe_pairs_in_catalog": sum(
            1 for row in cve_cwe_pairs if row.get("cwe_in_catalog", True)
        ),
        "cwe_capec_pairs": len(cwe_capec_pairs),
        "candidate_rows": len(candidate_rows),
        "candidate_rows_with_candidates": sum(
            1 for row in candidate_rows if row["candidate_capec_ids"]
        ),
        "candidate_capec_links": sum(len(row["candidate_capec_ids"]) for row in candidate_rows),
        "cve2capec_reference_rows": len(references),
        "cve2capec_reference_rows_with_capec": sum(
            1 for reference in references.values() if reference.capec_ids
        ),
        "cve2capec_matched_selected": len(set(references) & selected_ids),
        "exploit_rows_total": len(exploits),
        "exploit_rows_with_selected_cve": sum(1 for row in exploit_rows if row["cve_ids"]),
        "splits": {name: len(ids) for name, ids in splits.items()},
        "cwe_catalog": dict(cwe_meta),
        "capec_catalog": dict(capec_meta),
    }
