"""Opt-in downloader for the paper-reproduction dataset.

This script is intentionally explicit: importing the package never downloads
anything. It fetches public snapshots only:

* NVD annual CVE feeds (JSON gzip)
* MITRE CWE and CAPEC XML catalogs
* ExploitDB CSV metadata (no exploit source files)
* CVE2CAPEC reference JSONL gzip files (evaluation only)

Examples::

    python scripts/download_reproduction_data.py --source all
    python scripts/download_reproduction_data.py --source all --start-year 2002 --end-year 2023
    python scripts/download_reproduction_data.py --source nvd --start-year 2002 --end-year 2026
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import requests

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from scripts.download_data import CAPEC_URL, CWE_URL, _extract_xml, _save_catalog
from vuln2action.config import project_root

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CVE2CAPEC_URL = (
    "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/database/CVE-{year}.jsonl.gz"
)
USER_AGENT = "vuln2action-lab/0.2"


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _download(url: str, dest: Path, timeout: float, force: bool = False) -> Path:
    if dest.exists() and dest.stat().st_size > 0 and not force:
        print(f"skip existing {dest}", flush=True)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_suffix(dest.suffix + ".part")
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            print(f"downloading {url}", flush=True)
            response = requests.get(
                url,
                timeout=(30, timeout),
                headers={"User-Agent": USER_AGENT},
            )
            response.raise_for_status()
            content = response.content
            if not content:
                raise requests.RequestException("empty response body")
            temporary.write_bytes(content)
            temporary.replace(dest)
            print(f"wrote {dest} ({dest.stat().st_size} bytes)", flush=True)
            return dest
        except requests.RequestException as exc:
            last_error = exc
            if temporary.exists():
                temporary.unlink()
            print(f"retry {attempt + 1}/3 after {exc}", flush=True)
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"failed to download {url}: {last_error}")


def download_nvd_feeds(
    out_dir: Path,
    start_year: int,
    end_year: int,
    timeout: float,
    force: bool,
) -> list[Path]:
    written: list[Path] = []
    for year in range(start_year, end_year + 1):
        url = NVD_FEED_URL.format(year=year)
        dest = out_dir / "nvd" / f"nvdcve-2.0-{year}.json.gz"
        try:
            written.append(_download(url, dest, timeout, force=force))
        except RuntimeError as exc:
            print(f"skip {year}: {exc}", flush=True)
        time.sleep(0.5)
    return written


def download_catalogs(out_dir: Path, timeout: float, force: bool) -> list[Path]:
    written: list[Path] = []
    for url, relative in (
        (CWE_URL, Path("cwe") / "cwec_latest.xml"),
        (CAPEC_URL, Path("capec") / "capec_latest.xml"),
    ):
        dest = out_dir / relative
        if dest.exists() and not force:
            print(f"skip existing {dest}")
            written.append(dest)
            continue
        content = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
        content.raise_for_status()
        written.append(_save_catalog(_extract_xml(content.content), dest))
        print(f"wrote {dest} ({dest.stat().st_size} bytes)")
    return written


def download_exploitdb(out_dir: Path, timeout: float, force: bool) -> list[Path]:
    dest = out_dir / "exploitdb" / "files_exploits.csv"
    return [_download(EXPLOITDB_CSV_URL, dest, timeout, force=force)]


def download_cve2capec(
    out_dir: Path,
    start_year: int,
    end_year: int,
    timeout: float,
    force: bool,
) -> list[Path]:
    written: list[Path] = []
    for year in range(start_year, end_year + 1):
        url = CVE2CAPEC_URL.format(year=year)
        dest = out_dir / "cve2capec" / f"CVE-{year}.jsonl.gz"
        try:
            written.append(_download(url, dest, timeout, force=force))
        except RuntimeError as exc:
            print(f"skip CVE2CAPEC {year}: {exc}")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download public snapshots for the Vuln2Action reproduction dataset."
    )
    parser.add_argument(
        "--source",
        choices=["all", "nvd", "cwe", "capec", "exploitdb", "cve2capec"],
        default="all",
    )
    parser.add_argument("--out", default="data/raw")
    parser.add_argument("--start-year", type=int, default=2002)
    parser.add_argument("--end-year", type=int, default=2023)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.start_year > args.end_year:
        parser.error("--start-year must be <= --end-year")

    out_dir = _resolve(args.out)
    jobs = (
        ["nvd", "cwe", "capec", "exploitdb", "cve2capec"] if args.source == "all" else [args.source]
    )
    written: list[Path] = []
    for job in jobs:
        if job == "nvd":
            written.extend(
                download_nvd_feeds(
                    out_dir, args.start_year, args.end_year, args.timeout, args.force
                )
            )
        elif job == "cwe" or job == "capec":
            # The catalog helper downloads both; keep only the requested file.
            catalogs = download_catalogs(out_dir, args.timeout, args.force)
            wanted = "cwe" if job == "cwe" else "capec"
            written.extend(path for path in catalogs if wanted in path.parts)
        elif job == "exploitdb":
            written.extend(download_exploitdb(out_dir, args.timeout, args.force))
        else:
            written.extend(
                download_cve2capec(
                    out_dir, args.start_year, args.end_year, args.timeout, args.force
                )
            )

    print(f"downloaded {len(written)} files under {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
