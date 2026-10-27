"""Opt-in snapshot downloader (Phase 2). Never runs automatically.

Examples::

    python scripts/download_data.py --source nvd --cve CVE-2021-44228
    python scripts/download_data.py --source nvd --keyword apache --max-records 20
    python scripts/download_data.py --source cwe
    python scripts/download_data.py --source capec
    python scripts/download_data.py --source all

Snapshots land under ``data/raw/`` (git-ignored). Nothing is downloaded unless
this script is invoked explicitly. Set ``NVD_API_KEY`` to use the higher NVD
rate limit; the client throttles to the public limit otherwise.
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

import requests

from vuln2action.config import project_root
from vuln2action.connectors.nvd import NvdClient, save_nvd_snapshot

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _download(url: str, timeout: float) -> bytes:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.content


def _extract_xml(content: bytes) -> bytes:
    if not zipfile.is_zipfile(io.BytesIO(content)):
        return content
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if not names:
            raise ValueError("catalog archive contains no XML file")
        return archive.read(names[0])


def _save_catalog(content: bytes, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _nvd_query_params(args: argparse.Namespace) -> dict[str, str]:
    """Translate optional CLI date windows into NVD query parameters."""
    params: dict[str, str] = {}
    for prefix, start, end in (
        ("lastMod", args.last_mod_start, args.last_mod_end),
        ("pub", args.pub_start, args.pub_end),
    ):
        if bool(start) != bool(end):
            raise ValueError(
                f"--{prefix.lower()}-start and --{prefix.lower()}-end must be used together"
            )
        if start and end:
            params[f"{prefix}StartDate"] = start
            params[f"{prefix}EndDate"] = end
    return params


def download_nvd(args: argparse.Namespace) -> list[Path]:
    client = NvdClient(
        api_key=os.environ.get(args.api_key_env) or None,
        timeout=args.timeout,
    )
    out_dir = _resolve(args.out) / "nvd"
    if args.cve:
        if _nvd_query_params(args) or args.keyword:
            raise ValueError("--cve cannot be combined with keyword or date-range filters")
        vulnerabilities = [client.fetch_cve(cve_id) for cve_id in args.cve]
    else:
        params: dict[str, str] = _nvd_query_params(args)
        if args.keyword:
            params["keywordSearch"] = args.keyword
        vulnerabilities = list(
            client.iter_cves(
                max_records=args.max_records,
                results_per_page=args.results_per_page,
                **params,
            )
        )
    if not vulnerabilities:
        raise RuntimeError("NVD returned no records for the requested query")
    payload = {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": datetime.now(UTC).isoformat(),
        "startIndex": 0,
        "resultsPerPage": len(vulnerabilities),
        "totalResults": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
    return [save_nvd_snapshot(payload, out_dir)]


def download_cwe(args: argparse.Namespace) -> list[Path]:
    content = _extract_xml(_download(CWE_URL, args.timeout))
    return [_save_catalog(content, _resolve(args.out) / "cwe" / "cwec_latest.xml")]


def download_capec(args: argparse.Namespace) -> list[Path]:
    content = _extract_xml(_download(CAPEC_URL, args.timeout))
    return [_save_catalog(content, _resolve(args.out) / "capec" / "capec_latest.xml")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Explicitly download vulnerability snapshots (offline by default)."
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=["nvd", "cwe", "capec", "all"],
        help="Which snapshot(s) to download.",
    )
    parser.add_argument("--out", default="data/raw", help="Snapshot root (default: data/raw).")
    parser.add_argument("--cve", action="append", default=[], help="NVD CVE id (repeatable).")
    parser.add_argument("--keyword", default="", help="NVD keyword search when no --cve is given.")
    parser.add_argument("--last-mod-start", default="", help="NVD lastModified start (ISO-8601).")
    parser.add_argument("--last-mod-end", default="", help="NVD lastModified end (ISO-8601).")
    parser.add_argument("--pub-start", default="", help="NVD published start (ISO-8601).")
    parser.add_argument("--pub-end", default="", help="NVD published end (ISO-8601).")
    parser.add_argument(
        "--max-records",
        type=int,
        default=100,
        help="Maximum NVD records to download (default: 100).",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=200,
        help="NVD page size, 1-2000 (default: 200).",
    )
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--api-key-env",
        default="NVD_API_KEY",
        help="Environment variable holding an optional NVD API key.",
    )
    args = parser.parse_args(argv)
    if args.max_records < 1:
        parser.error("--max-records must be >= 1")
    if not 1 <= args.results_per_page <= 2000:
        parser.error("--results-per-page must be between 1 and 2000")

    jobs = ["nvd", "cwe", "capec"] if args.source == "all" else [args.source]
    written: list[Path] = []
    try:
        for job in jobs:
            if job == "nvd":
                written.extend(download_nvd(args))
            elif job == "cwe":
                written.extend(download_cwe(args))
            else:
                written.extend(download_capec(args))
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    for path in written:
        print(f"wrote {path}")
    print("Snapshots are raw inputs; run scripts/build_dataset.py to normalise them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
