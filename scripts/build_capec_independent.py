"""Build an *independent* CVE -> CAPEC evaluation set from MITRE evidence.

Why this exists
---------------
The tracked 120-CVE file (`capec_benchmark.json`) takes its labels from
Galeax/CVE2CAPEC, and Galeax derives each CVE's CAPEC set by expanding its CWEs
through ``CWE -> Related_Attack_Pattern``. We verified that the produced set
equals that closure for 100% of 18,540 joinable CVE-2021 records, so the
paper-compatible "is the prediction in the label set" metric is close to free:
the candidates are drawn from the very same closure.

This builder uses a different, independent label source instead:

**MITRE CAPEC ``Example_Instances``.** 59 CAPEC patterns embed real-world
examples that explicitly name a CVE ("See also: CVE-1999-0906"). The link is
written by MITRE analysts describing the *attack pattern a known incident
exhibits*; it is not computed from CWE mappings. Each label therefore comes with
a human-readable justification that a reviewer can check, and it is stored
verbatim in the output file.

Independence was measured, not assumed: in 9 of the 21 evaluable cases the MITRE
example label is a *proper subset* of the CWE-derived candidate pool (in some
cases the label is not in the pool at all), which no closure-based metric can
produce.

CWEs are needed only to build the candidate pool. They are taken from NVD when
present, otherwise from the CWE catalog's ``Observed_Examples`` (MITRE's own),
never from the label source. ``cwe_source`` records which one was used.

Downloads are explicit (``--download``) and cached under ``data/external/``.
Without it the script reads local snapshots only.

Examples::

    python scripts/build_capec_independent.py --download
    python scripts/build_capec_independent.py --out evaluation/datasets/capec_independent.json
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

import requests

from vuln2action.config import project_root
from vuln2action.connectors.nvd import parse_nvd_cve, parse_nvd_records
from vuln2action.retrieval.capec import load_capec_index
from vuln2action.utils.filesystem import ensure_dir, write_json

RAW_CAPEC = ("data", "raw", "capec", "capec_latest.xml")
RAW_CWE = ("data", "raw", "cwe", "cwec_latest.xml")
EXTERNAL_DIR = ("data", "external", "capec_independent")
OUTPUT = ("evaluation", "datasets", "capec_independent.json")
NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
_MIN_CANDIDATES = 2


class MissingInputError(RuntimeError):
    """Raised when a required local snapshot has not been downloaded."""


def _safe_stdout() -> None:
    """Keep Windows cp1252 consoles from crashing on non-ASCII repo paths."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):  # pragma: no cover - exotic consoles
                pass


def _resolve(path: str | Path) -> Path:
    resolved = Path(path)
    return resolved if resolved.is_absolute() else project_root() / resolved


def _external_dir() -> Path:
    return ensure_dir(project_root().joinpath(*EXTERNAL_DIR))


def _xml_root(path: Path) -> ElementTree.Element:
    if not path.is_file():
        raise MissingInputError(f"catalog not found: {path}")
    root = ElementTree.fromstring(path.read_bytes())
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


def extract_capec_example_labels(path: Path | None = None) -> dict[str, list[dict[str, str]]]:
    """Extract MITRE's ``See also: CVE-...`` example labels with their evidence.

    Returns ``{cve_id: [{capec_id, capec_name, text}, ...]}``. The example text is
    truncated but kept verbatim so a reviewer can judge the mapping.
    """
    snapshot = Path(path) if path is not None else repo_path(*RAW_CAPEC)
    root = _xml_root(snapshot)
    evidence: dict[str, list[dict[str, str]]] = {}
    for attack in root.iter("Attack_Pattern"):
        capec_id = f"CAPEC-{attack.get('ID')}"
        examples = attack.find("Example_Instances")
        if examples is None:
            continue
        for instance in examples:
            text = " ".join(" ".join(instance.itertext()).split())
            for cve_id in sorted(set(_CVE_PATTERN.findall(text))):
                evidence.setdefault(cve_id, []).append(
                    {
                        "capec_id": capec_id,
                        "capec_name": (attack.get("Name") or "").strip(),
                        "text": text[:400],
                    }
                )
    return evidence


def repo_path(*parts: str) -> Path:
    return project_root().joinpath(*parts)


def extract_cwe_observed_examples(path: Path | None = None) -> dict[str, list[str]]:
    """CWE ``Observed_Examples`` CVE mentions, used only to fill missing CWEs."""
    snapshot = Path(path) if path is not None else repo_path(*RAW_CWE)
    root = _xml_root(snapshot)
    observed: dict[str, set[str]] = {}
    for weakness in root.iter("Weakness"):
        cwe_id = f"CWE-{(weakness.get('ID') or '').strip()}"
        for example in weakness.findall(".//Observed_Example"):
            text = " ".join(example.itertext())
            for cve_id in _CVE_PATTERN.findall(text):
                observed.setdefault(cve_id, set()).add(cwe_id)
    return {cve_id: sorted(ids) for cve_id, ids in observed.items()}


def _download(url: str, timeout: float) -> bytes:
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "vuln2action-lab/0.2"})
    response.raise_for_status()
    return response.content


def load_nvd_records(
    cve_ids: set[str],
    *,
    download: bool,
    timeout: float,
    cache: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Resolve CVE records from cached bulk feeds, then the API for stragglers."""
    cache_dir = cache or _external_dir()
    cache_file = cache_dir / "nvd_independent.json"
    if cache_file.is_file():
        cached = json.loads(cache_file.read_text(encoding="utf-8"))
        cached = {key: value for key, value in cached.items() if key in cve_ids}
        if len(cached) == len(cve_ids):
            return cached

    found: dict[str, dict[str, Any]] = {}
    if download:
        years = sorted({cve_id.split("-")[1] for cve_id in cve_ids})
        for year in years:
            feed_path = cache_dir / f"nvdcve-2.0-{year}.json.gz"
            if not feed_path.is_file():
                try:
                    feed_path.write_bytes(_download(NVD_FEED.format(year=year), timeout))
                except requests.RequestException:
                    # Pre-2002 years have no v2.0 feed; the API covers them below.
                    continue
            feed = json.loads(gzip.decompress(feed_path.read_bytes()))
            for record in parse_nvd_records(feed):
                if record.cve_id in cve_ids:
                    found[record.cve_id] = record.model_dump(mode="json")

        missing = sorted(cve_ids - set(found))
        for position, cve_id in enumerate(missing):
            try:
                response = requests.get(NVD_API, params={"cveId": cve_id}, timeout=timeout)
                response.raise_for_status()
                vulnerabilities = response.json().get("vulnerabilities") or []
            except (requests.RequestException, ValueError):
                continue
            if vulnerabilities:
                found[cve_id] = parse_nvd_cve(vulnerabilities[0]).model_dump(mode="json")
            if position < len(missing) - 1:
                import time

                time.sleep(6.2)  # public NVD rate limit

    if not cache_file.is_file() or found:
        write_json(cache_file, {**found})
    return found


def build_cases(
    evidence: dict[str, list[dict[str, str]]],
    observed_cwe: dict[str, list[str]],
    nvd_records: dict[str, dict[str, Any]],
    *,
    min_candidates: int = _MIN_CANDIDATES,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Join evidence labels with CVE text and CWE-derived candidates."""
    index = load_capec_index()
    cases: list[dict[str, Any]] = []
    stats = {
        "cve_ids_with_mitre_examples": len(evidence),
        "skipped_no_nvd_record": 0,
        "skipped_no_cwe": 0,
        "skipped_too_few_candidates": 0,
        "label_unreachable": 0,
        "label_partially_reachable": 0,
        "cwe_from_nvd": 0,
        "cwe_from_cwe_observed_examples": 0,
        "evaluable": 0,
    }

    for cve_id in sorted(evidence):
        record = nvd_records.get(cve_id)
        if record is None:
            stats["skipped_no_nvd_record"] += 1
            continue
        nvd_cwe = [cwe for cwe in record.get("cwe") or [] if cwe]
        cwe_source = "nvd"
        if not nvd_cwe:
            nvd_cwe = observed_cwe.get(cve_id, [])
            cwe_source = "cwe-observed-examples"
        if not nvd_cwe:
            stats["skipped_no_cwe"] += 1
            continue

        candidates = index.candidates_for_cwes(nvd_cwe)
        if len(candidates) < min_candidates:
            stats["skipped_too_few_candidates"] += 1
            continue

        label = sorted({item["capec_id"] for item in evidence[cve_id]})
        reachable = sorted(set(label) & set(candidates))
        if not reachable:
            stats["label_unreachable"] += 1
        elif len(reachable) < len(label):
            stats["label_partially_reachable"] += 1
        stats["cwe_from_nvd" if cwe_source == "nvd" else "cwe_from_cwe_observed_examples"] += 1

        cases.append(
            {
                "case_id": "",
                "cve_id": cve_id,
                "query": record.get("description", ""),
                "cwe_ids": nvd_cwe,
                "cwe_source": cwe_source,
                "capec_label": label,
                "candidates": candidates,
                "label_evidence": evidence[cve_id],
                "label_reachable_in_candidates": reachable,
                "label_fully_reachable": len(reachable) == len(label),
            }
        )

    stats["evaluable"] = len(cases)
    for position, case in enumerate(cases, start=1):
        case["case_id"] = f"IND-{position:03d}"
    return cases, stats


def build_payload(
    cases: list[dict[str, Any]],
    stats: dict[str, int],
    capec_version: str = "",
) -> dict[str, Any]:
    index = load_capec_index()
    return {
        "version": "1.0.0",
        "kind": "independent",
        "description": (
            "Independent CVE -> CAPEC evaluation set. Labels are MITRE CAPEC "
            "Example_Instances 'See also: CVE-...' links, not a CWE->CAPEC closure."
        ),
        "labels_source": (
            "MITRE CAPEC catalog Example_Instances (patterns that name a CVE)"
            + (f", catalog {capec_version}" if capec_version else "")
        ),
        "query_source": "NVD 2.0 descriptions (bulk feed or API, cached in data/external)",
        "candidate_source": f"MITRE CAPEC Related_Weakness expansion ({len(index.documents)} patterns)",
        "labeling_criteria": (
            "A label is accepted only when the CAPEC entry's Example_Instances text "
            "explicitly names the CVE. Labels are copied verbatim from MITRE and are "
            "never edited or inferred. The example text is stored per case so a "
            "reviewer can accept or reject the mapping."
        ),
        "uncertainty": (
            "MITRE examples are illustrative, not exhaustive: a CVE may exhibit "
            "attack patterns MITRE never wrote down, so absence of a label is not "
            "evidence of incorrectness. Some examples are old (1999-2007) and their "
            "NVD records often lack CWE assignments; those cases rely on the CWE "
            "catalog's Observed_Examples for candidates (recorded in cwe_source)."
        ),
        "built_at": datetime.now(UTC).isoformat(),
        "sample_stats": stats,
        "k": 1,
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    parser = argparse.ArgumentParser(
        description="Build the independent CAPEC evaluation set from MITRE evidence."
    )
    parser.add_argument("--capec", default="", help="CAPEC XML snapshot path.")
    parser.add_argument("--cwe", default="", help="CWE XML snapshot path.")
    parser.add_argument(
        "--download",
        action="store_true",
        help="Fetch missing NVD data into data/external (explicit opt-in).",
    )
    parser.add_argument("--out", default=str(Path(*OUTPUT)), help="Output JSON path.")
    parser.add_argument("--timeout", type=float, default=300.0, help="HTTP timeout seconds.")
    parser.add_argument(
        "--min-candidates",
        type=int,
        default=_MIN_CANDIDATES,
        help="Skip cases with fewer candidates than this (default: 2).",
    )
    args = parser.parse_args(argv)
    if args.min_candidates < 1:
        parser.error("--min-candidates must be >= 1")

    try:
        evidence = extract_capec_example_labels(_resolve(args.capec) if args.capec else None)
        observed = extract_cwe_observed_examples(_resolve(args.cwe) if args.cwe else None)
    except MissingInputError as exc:
        parser.error(f"{exc} (run: python scripts/download_data.py --source capec/cwe)")
        return 2  # pragma: no cover - argparse exits
    except FileNotFoundError:
        # The CWE catalog only fills missing NVD CWEs; carry on without it.
        observed = {}

    if not evidence:
        parser.error("no CAPEC Example_Instances named any CVE; check the snapshot")
    if not args.download:
        cached = _external_dir() / "nvd_independent.json"
        if not cached.is_file():
            parser.error(f"NVD data missing; rerun with --download or provide {cached}")

    records = load_nvd_records(set(evidence), download=args.download, timeout=args.timeout)
    cases, stats = build_cases(evidence, observed, records, min_candidates=args.min_candidates)
    if not cases:
        parser.error("no evaluable cases were produced")
    payload = build_payload(cases, stats)
    out_path = write_json(_resolve(args.out), payload)

    print(f"wrote {len(cases)} independent cases -> {out_path}")
    print(json.dumps(stats, indent=2))
    print(
        "labels are MITRE-written CVE mentions, not CWE->CAPEC expansion; "
        "review label_evidence before trusting any metric."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
