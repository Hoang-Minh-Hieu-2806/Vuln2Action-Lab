"""Build the paper-reproduction dataset from local snapshots.

This script is offline. Run ``scripts/download_reproduction_data.py`` first.

Outputs (JSONL unless noted):

* ``cves.jsonl``                     selected CVE records
* ``cwe.json``                       CWE catalog with relations
* ``capec.json``                     CAPEC catalog with execution flows
* ``cve_cwe.jsonl``                  CVE-CWE pairs
* ``cwe_capec.jsonl``                CWE-CAPEC pairs
* ``cve_capec_candidates.jsonl``     candidate CAPECs per CVE-CWE pair
* ``cve2capec_reference.jsonl``      evaluation-only CVE2CAPEC mapping
* ``exploitdb.jsonl``                ExploitDB metadata (no source code)
* ``splits.json``                    train/validation/evaluation split
* ``stats.json``                     counts and provenance
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.config import project_root
from vuln2action.connectors.cve2capec import load_cve2capec
from vuln2action.connectors.exploitdb import parse_exploitdb_csv
from vuln2action.connectors.reproduction import (
    build_candidate_rows,
    build_cve_cwe_pairs,
    build_cwe_capec_pairs,
    build_reference_rows,
    catalog_metadata,
    dataset_stats,
    exploit_rows_for_selected,
    load_nvd_feeds,
    make_splits,
    parse_catalogs,
    sample_records_by_year,
    select_newest_records,
)
from vuln2action.utils.filesystem import write_json, write_jsonl


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the Vuln2Action reproduction dataset from local snapshots."
    )
    parser.add_argument("--nvd-feed-dir", default="data/raw/nvd")
    parser.add_argument("--cwe", default="data/raw/cwe/cwec_latest.xml")
    parser.add_argument("--capec", default="data/raw/capec/capec_latest.xml")
    parser.add_argument("--exploitdb", default="data/raw/exploitdb/files_exploits.csv")
    parser.add_argument("--cve2capec", default="data/raw/cve2capec")
    parser.add_argument("--out-dir", default="data/processed/reproduction")
    parser.add_argument("--target-cves", type=int, default=55_000)
    parser.add_argument("--start-year", type=int, default=2002)
    parser.add_argument("--end-year", type=int, default=2023)
    parser.add_argument(
        "--selection-strategy",
        choices=["stratified", "newest"],
        default="stratified",
        help="stratified = paper-faithful sample by year; newest = latest published CVEs.",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    if args.target_cves < 1:
        parser.error("--target-cves must be >= 1")
    if args.start_year > args.end_year:
        parser.error("--start-year must be <= --end-year")

    feed_dir = _resolve(args.nvd_feed_dir)
    cwe_path = _resolve(args.cwe)
    capec_path = _resolve(args.capec)
    exploitdb_path = _resolve(args.exploitdb)
    cve2capec_path = _resolve(args.cve2capec)
    for path, label in (
        (feed_dir, "NVD feed directory"),
        (cwe_path, "CWE catalog"),
        (capec_path, "CAPEC catalog"),
        (exploitdb_path, "ExploitDB CSV"),
        (cve2capec_path, "CVE2CAPEC directory"),
    ):
        if not path.exists():
            parser.error(f"{label} not found: {path}")

    print("loading NVD feeds...")
    records_by_year = load_nvd_feeds(feed_dir, args.start_year, args.end_year)
    if not records_by_year:
        parser.error(f"no NVD annual feeds found under {feed_dir}")

    if args.selection_strategy == "newest":
        selected = select_newest_records(records_by_year, args.target_cves)
    else:
        selected = sample_records_by_year(records_by_year, args.target_cves, seed=args.seed)
    if not selected:
        parser.error("NVD selection produced no records")
    selected_ids = {record.cve_id for record in selected}
    print(
        f"selected {len(selected)} CVEs ({args.selection_strategy}) "
        f"from {sum(len(v) for v in records_by_year.values())}"
    )

    print("parsing CWE/CAPEC catalogs...")
    cwes, capecs = parse_catalogs(cwe_path, capec_path)
    known_cwe_ids = {record.cwe_id for record in cwes}
    cve_cwe_pairs = build_cve_cwe_pairs(selected, known_cwe_ids)
    cwe_capec_pairs = build_cwe_capec_pairs(cwes, capecs)
    candidate_rows = build_candidate_rows(selected, cwe_capec_pairs, known_cwe_ids)

    print("loading CVE2CAPEC evaluation references...")
    references = load_cve2capec(cve2capec_path, selected_ids)
    reference_rows = build_reference_rows(references)

    print("parsing ExploitDB metadata...")
    exploits = parse_exploitdb_csv(exploitdb_path)
    exploit_rows = exploit_rows_for_selected(exploits, selected_ids)

    reference_ids = [cve_id for cve_id, reference in references.items() if reference.capec_ids]
    splits = make_splits(selected_ids, reference_ids, seed=args.seed)
    stats = dataset_stats(
        records_by_year=records_by_year,
        selected=selected,
        cwes=cwes,
        capecs=capecs,
        cve_cwe_pairs=cve_cwe_pairs,
        cwe_capec_pairs=cwe_capec_pairs,
        candidate_rows=candidate_rows,
        references=references,
        exploits=exploits,
        exploit_rows=exploit_rows,
        splits=splits,
        target=args.target_cves,
        seed=args.seed,
        selection_strategy=args.selection_strategy,
        cwe_meta=catalog_metadata(cwe_path),
        capec_meta=catalog_metadata(capec_path),
    )

    out_dir = _resolve(args.out_dir)
    write_jsonl(out_dir / "cves.jsonl", [record.model_dump(mode="json") for record in selected])
    write_json(out_dir / "cwe.json", [record.model_dump(mode="json") for record in cwes])
    write_json(out_dir / "capec.json", [record.model_dump(mode="json") for record in capecs])
    write_jsonl(out_dir / "cve_cwe.jsonl", cve_cwe_pairs)
    write_jsonl(out_dir / "cwe_capec.jsonl", cwe_capec_pairs)
    write_jsonl(out_dir / "cve_capec_candidates.jsonl", candidate_rows)
    write_jsonl(out_dir / "cve2capec_reference.jsonl", reference_rows)
    write_jsonl(out_dir / "exploitdb.jsonl", exploit_rows)
    write_json(out_dir / "splits.json", splits)
    write_json(out_dir / "stats.json", stats)

    print(f"wrote dataset to {out_dir}")
    print(
        "summary: "
        f"{stats['selected_cves']} CVEs, "
        f"{stats['cve_cwe_pairs']} CVE-CWE pairs, "
        f"{stats['cwe_capec_pairs']} CWE-CAPEC pairs, "
        f"{stats['exploit_rows_with_selected_cve']} exploits matched"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
