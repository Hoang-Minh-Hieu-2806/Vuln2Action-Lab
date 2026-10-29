"""Build a CVE -> CWE -> CAPEC benchmark with traceable ground-truth labels.

Labels come from `Galeax/CVE2CAPEC <https://github.com/Galeax/CVE2CAPEC>`_ (the
same reference used by the paper, ref. [55]) and queries are the real NVD
descriptions. Nothing here is written by hand and no label is generated from the
CAPEC catalog we rank against -- the two inputs are separate downloads.

**Important property of these labels (measured, not assumed).** Galeax derives
each CVE's CAPEC set by expanding its CWEs through ``CWE -> Related_Attack_Pattern``.
We verified on all 18,540 joinable CVE-2021 records that the published CAPEC set
equals that expansion exactly, 100% of the time. So a metric of the form "is the
predicted CAPEC inside the label set" (the protocol the paper reports as 89/100)
is close to free: every candidate already comes from that same expansion. The
builder therefore also stores each CVE's NVD CWE list and the candidate set, which
lets the evaluator report a non-vacuous score alongside the paper-compatible one.

Downloads are explicit (``--download``) and cached under ``data/external/`` which
is git-ignored. Without ``--download`` the script only reads local snapshots.

Examples::

    # Fetch NVD + Galeax inputs, then build a 120-case benchmark
    python scripts/build_capec_benchmark.py --download --year 2021 --size 120

    # Rebuild from already-downloaded snapshots
    python scripts/build_capec_benchmark.py --year 2021 --size 120
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

import requests

from vuln2action.config import project_root
from vuln2action.connectors.nvd import parse_nvd_records
from vuln2action.retrieval.capec import load_capec_index
from vuln2action.utils.filesystem import ensure_dir, write_json

NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
GALEAX_DB = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/database/CVE-{year}.jsonl.gz"
GALEAX_COMMIT = "https://api.github.com/repos/Galeax/CVE2CAPEC/commits?per_page=1"
EXTERNAL_DIR = ("data", "external", "capec_benchmark")
OUTPUT = ("evaluation", "datasets", "capec_benchmark.json")


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _external_dir() -> Path:
    return ensure_dir(project_root().joinpath(*EXTERNAL_DIR))


def _download(url: str, timeout: float) -> bytes:
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "vuln2action-lab/0.2"})
    response.raise_for_status()
    return response.content


def fetch_nvd_feed(year: str, timeout: float = 300.0) -> Path:
    path = _external_dir() / f"nvdcve-2.0-{year}.json.gz"
    if not path.is_file():
        path.write_bytes(_download(NVD_FEED.format(year=year), timeout))
    return path


def fetch_galeax_db(year: str, timeout: float = 300.0) -> Path:
    path = _external_dir() / f"cve2capec-{year}.jsonl.gz"
    if not path.is_file():
        path.write_bytes(_download(GALEAX_DB.format(year=year), timeout))
    return path


def galeax_commit_sha(timeout: float = 60.0) -> str:
    try:
        payload = json.loads(_download(GALEAX_COMMIT, timeout))
        return str(payload[0]["sha"]) if payload else ""
    except (OSError, ValueError, KeyError, IndexError, requests.RequestException):
        return ""


def load_galeax_labels(path: Path) -> dict[str, dict[str, Any]]:
    """Read the per-year JSONL (one ``{"CVE-...": {...}}`` object per line)."""
    labels: dict[str, dict[str, Any]] = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            chunk = json.loads(line)
            if isinstance(chunk, dict):
                labels.update(chunk)
    return labels


def _normalise_capec(values: Any) -> list[str]:
    out: list[str] = []
    for item in values or []:
        text = str(item).strip().upper()
        if not text:
            continue
        capec_id = text if text.startswith("CAPEC-") else f"CAPEC-{text}"
        if capec_id not in out:
            out.append(capec_id)
    return sorted(out)


def build_cases(
    year: str,
    size: int,
    seed: int,
    nvd_path: Path,
    galeax_path: Path,
    *,
    max_candidates: int = 120,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Join NVD descriptions with Galeax labels and sample ``size`` cases.

    Candidates are recomputed from the tracked CAPEC catalog so the file records
    exactly what each method was allowed to rank. Selection is deterministic for
    a given ``seed`` and sorted CVE ids.
    """
    index = load_capec_index()
    feed = json.loads(gzip.decompress(nvd_path.read_bytes()))
    records = {record.cve_id: record for record in parse_nvd_records(feed)}
    labels = load_galeax_labels(galeax_path)

    eligible: list[dict[str, Any]] = []
    stats = {
        "nvd_records": len(records),
        "galeax_records": len(labels),
        "skipped_no_label": 0,
        "skipped_no_cwe": 0,
        "skipped_no_candidate": 0,
        "skipped_large_candidate_set": 0,
        "eligible": 0,
    }
    for cve_id in sorted(records):
        record = records[cve_id]
        label = labels.get(cve_id)
        if not label:
            stats["skipped_no_label"] += 1
            continue
        label_capec = _normalise_capec(label.get("CAPEC"))
        if not label_capec:
            stats["skipped_no_label"] += 1
            continue
        if not record.cwe:
            stats["skipped_no_cwe"] += 1
            continue
        candidates = index.candidates_for_cwes(record.cwe)
        if not candidates:
            stats["skipped_no_candidate"] += 1
            continue
        if len(candidates) > max_candidates:
            # Huge candidate sets make a single-choice label noisy and slow; the
            # cap is recorded so the filter is visible rather than silent.
            stats["skipped_large_candidate_set"] += 1
            continue
        eligible.append(
            {
                "case_id": "",
                "cve_id": cve_id,
                "query": record.description,
                "cwe_ids": list(record.cwe),
                "capec_label": label_capec,
                "candidates": candidates,
                "label_source_cwe": sorted(
                    _normalise_cwe(label.get("CWE")),
                ),
                "nvd_cwe_matches_label_source": sorted(record.cwe)
                == _normalise_cwe(label.get("CWE")),
            }
        )
    stats["eligible"] = len(eligible)

    random.Random(seed).shuffle(eligible)
    chosen = sorted(eligible[:size], key=lambda case: case["cve_id"])
    for position, case in enumerate(chosen, start=1):
        case["case_id"] = f"CAPEC-{year}-{position:03d}"
    stats["selected"] = len(chosen)
    return chosen, stats


def _normalise_cwe(values: Any) -> list[str]:
    out: list[str] = []
    for item in values or []:
        text = str(item).strip().upper()
        if not text:
            continue
        cwe_id = text if text.startswith("CWE-") else f"CWE-{text}"
        if cwe_id not in out:
            out.append(cwe_id)
    return sorted(out)


def build_payload(
    year: str,
    size: int,
    seed: int,
    cases: list[dict[str, Any]],
    stats: dict[str, int],
    galeax_sha: str,
) -> dict[str, Any]:
    index = load_capec_index()
    return {
        "version": "1.0.0",
        "description": (
            "CVE description -> CAPEC relevance benchmark. Queries are verbatim NVD "
            "descriptions; capec_label is the Galeax/CVE2CAPEC label set; candidates "
            "are the CWE->CAPEC expansion from the tracked MITRE catalog."
        ),
        "labels_source": (
            f"Galeax/CVE2CAPEC database/CVE-{year}.jsonl.gz (commit {galeax_sha or 'unknown'})"
        ),
        "query_source": f"NVD 2.0 feed nvdcve-2.0-{year}.json.gz",
        "candidate_source": f"MITRE CAPEC catalog ({len(index.documents)} patterns)",
        "label_semantics": (
            "Membership protocol: a prediction is 'correct' if it appears in "
            "capec_label, matching the paper's 89/100 protocol. Because Galeax "
            "labels are exactly the CWE->CAPEC expansion, membership is close to "
            "free for any method that ranks the same candidates; the evaluator "
            "also reports discriminative metrics."
        ),
        "built_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "requested_size": size,
        "sample_stats": stats,
        "k": 1,
        "cases": cases,
        "notes": (
            "Galeax CWE lists are not identical to NVD's CWE assignments "
            f"(labels match NVD for {sum(1 for c in cases if c['nvd_cwe_matches_label_source'])}"
            f"/{len(cases)} cases), so candidates come from NVD CWEs while labels "
            "come from Galeax. No label was invented or edited by hand."
        ),
    }


def _safe_stdout() -> None:
    """Keep Windows cp1252 consoles from crashing on non-ASCII repo paths."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(
        description="Build the CAPEC benchmark from NVD + Galeax/CVE2CAPEC snapshots."
    )
    parser.add_argument("--year", default="2021", help="NVD year feed to use (default: 2021).")
    parser.add_argument("--size", type=int, default=120, help="Number of cases (default: 120).")
    parser.add_argument("--seed", type=int, default=20210101, help="Sampling seed.")
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=120,
        help="Skip CVEs whose candidate set is larger than this (default: 120).",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Fetch missing NVD/Galeax snapshots into data/external/ (explicit opt-in).",
    )
    parser.add_argument("--out", default=str(Path(*OUTPUT)), help="Output benchmark JSON.")
    parser.add_argument("--timeout", type=float, default=300.0, help="HTTP timeout in seconds.")
    args = parser.parse_args(argv)
    if args.size < 1:
        parser.error("--size must be >= 1")
    if args.max_candidates < 1:
        parser.error("--max-candidates must be >= 1")

    nvd_path = _external_dir() / f"nvdcve-2.0-{args.year}.json.gz"
    galeax_path = _external_dir() / f"cve2capec-{args.year}.jsonl.gz"
    try:
        if args.download:
            nvd_path = fetch_nvd_feed(args.year, args.timeout)
            galeax_path = fetch_galeax_db(args.year, args.timeout)
        elif not nvd_path.is_file() or not galeax_path.is_file():
            parser.error(
                f"snapshots missing; rerun with --download or place them under {_external_dir()}"
            )
        sha = galeax_commit_sha(args.timeout) if args.download else ""
        cases, stats = build_cases(
            args.year,
            args.size,
            args.seed,
            nvd_path,
            galeax_path,
            max_candidates=args.max_candidates,
        )
    except (OSError, ValueError, RuntimeError, requests.RequestException) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits

    if not cases:
        parser.error("no eligible cases were found; check the year and inputs")

    payload = build_payload(args.year, args.size, args.seed, cases, stats, sha)
    out_path = write_json(_resolve(args.out), payload)
    print(f"wrote {len(cases)} cases -> {out_path}")
    print(json.dumps(stats, indent=2))
    if len(cases) < args.size:
        print(
            f"WARNING: requested {args.size} cases but only {len(cases)} were eligible "
            "after filtering; the shortfall is recorded in sample_stats.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
