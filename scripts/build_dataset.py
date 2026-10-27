"""Dataset builder (Phase 2): raw snapshots -> processed records.

Examples::

    python scripts/build_dataset.py --nvd data/raw/nvd --cwe data/raw/cwe/cwec_latest.xml
    python scripts/build_dataset.py --nvd data/raw/nvd --lab-map config/lab_map.json

This only reads local snapshots; it never downloads anything.
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
from vuln2action.connectors.dataset import (
    build_from_snapshots,
    load_lab_map,
    parse_catalogs,
    write_capec_dataset,
    write_cve_dataset,
    write_cwe_dataset,
)


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = _resolve(raw)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"snapshot path not found: {path}")
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build processed datasets from local snapshots.")
    parser.add_argument(
        "--nvd",
        action="append",
        default=[],
        help="NVD snapshot file or directory (repeatable).",
    )
    parser.add_argument("--cwe", default="", help="CWE XML catalog snapshot.")
    parser.add_argument("--capec", default="", help="CAPEC XML catalog snapshot.")
    parser.add_argument("--lab-map", default="", help="Optional JSON map: CVE id -> lab id.")
    parser.add_argument("--out-dir", default="data/processed", help="Output directory.")
    parser.add_argument(
        "--include-rejected",
        action="store_true",
        help="Keep NVD records whose vulnStatus is Rejected.",
    )
    args = parser.parse_args(argv)

    if not (args.nvd or args.cwe or args.capec):
        parser.error("provide at least one of --nvd, --cwe, --capec")

    out_dir = _resolve(args.out_dir)
    lab_map = load_lab_map(_resolve(args.lab_map)) if args.lab_map else {}
    snapshots = _expand(args.nvd)
    records = build_from_snapshots(
        snapshots,
        lab_map=lab_map,
        include_rejected=args.include_rejected,
    )
    cve_path = write_cve_dataset(records, out_dir / "cves.json")
    print(f"wrote {len(records)} CVEs -> {cve_path}")

    if args.cwe:
        cwes, _ = parse_catalogs(cwe_path=_resolve(args.cwe))
        cwe_path = write_cwe_dataset(cwes, out_dir / "cwe.json")
        print(f"wrote {len(cwes)} CWEs -> {cwe_path}")

    if args.capec:
        _, capecs = parse_catalogs(capec_path=_resolve(args.capec))
        capec_path = write_capec_dataset(capecs, out_dir / "capec.json")
        print(f"wrote {len(capecs)} CAPECs -> {capec_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
