"""Opt-in NVD API 2.0 client and CVE normaliser.

Nothing here runs at import time. Network access only happens when a caller
explicitly constructs :class:`NvdClient` and calls a fetch method (the
``scripts/download_data.py`` entry point does this on purpose, never the
pipeline). Public NVD rate limits are respected by default: 6 seconds between
requests without an API key and 0.6 seconds with one.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from vuln2action.domain import CveRecord
from vuln2action.utils.filesystem import write_json

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_OUT_DIR = "data/raw/nvd"
_RETRY_STATUS = {429, 500, 502, 503, 504}
_CWE_PATTERN = re.compile(r"^CWE-\d+$")


class NvdClient:
    """Small, polite NVD 2.0 client with optional pagination."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        timeout: float = 60.0,
        session: Any | None = None,
        min_interval: float | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 5.0,
        sleep: Any = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or None
        self.timeout = timeout
        self.session = session if session is not None else requests.Session()
        self.min_interval = (
            min_interval if min_interval is not None else (0.6 if self.api_key else 6.0)
        )
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._sleep = sleep
        self._last_request = 0.0

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "vuln2action-lab/0.2"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            self._sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                response = self.session.get(
                    self.base_url,
                    params=params,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_error = exc
            else:
                if response.status_code == 200:
                    payload = response.json()
                    if not isinstance(payload, dict):
                        raise ValueError("NVD response is not a JSON object")
                    return payload
                last_error = RuntimeError(f"NVD request failed with HTTP {response.status_code}")
                if response.status_code not in _RETRY_STATUS:
                    break
            if attempt < self.max_retries:
                self._sleep(self.backoff_seconds * (attempt + 1))
        raise RuntimeError(f"NVD request failed: {last_error}")

    def fetch_page(
        self,
        start_index: int = 0,
        results_per_page: int = 200,
        **params: Any,
    ) -> dict[str, Any]:
        query: dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
            **params,
        }
        return self._get({key: value for key, value in query.items() if value is not None})

    def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        """Return the raw ``{"cve": {...}}`` wrapper for one CVE."""
        payload = self._get({"cveId": cve_id.strip().upper()})
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            raise KeyError(f"CVE not found in NVD: {cve_id}")
        return vulnerabilities[0]

    def iter_cves(
        self,
        max_records: int = 100,
        results_per_page: int = 200,
        **params: Any,
    ) -> Iterator[dict[str, Any]]:
        """Yield raw ``{"cve": {...}}`` items, stopping at ``max_records``."""
        if max_records <= 0:
            return
        start_index = 0
        yielded = 0
        while yielded < max_records:
            page = self.fetch_page(
                start_index=start_index,
                results_per_page=results_per_page,
                **params,
            )
            vulnerabilities = page.get("vulnerabilities") or []
            if not vulnerabilities:
                return
            for item in vulnerabilities:
                yield item
                yielded += 1
                if yielded >= max_records:
                    return
            total = int(page.get("totalResults") or 0)
            start_index += len(vulnerabilities)
            if start_index >= total:
                return


def save_nvd_snapshot(
    payload: dict[str, Any],
    out_dir: str | Path = DEFAULT_OUT_DIR,
    name: str | None = None,
) -> Path:
    root = Path(out_dir)
    snapshot_name = name or f"nvd_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    return write_json(root / f"{snapshot_name}.json", payload)


def _english(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    for item in values:
        if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()
    for item in values:
        if isinstance(item, dict) and item.get("value"):
            return str(item["value"]).strip()
    return ""


def _pick_metric(entries: Any) -> dict[str, Any] | None:
    """Prefer NVD's own score, then a primary entry, then the first valid one."""
    if not isinstance(entries, list):
        return None
    valid = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("cvssData"), dict)
        and entry["cvssData"].get("baseScore") is not None
    ]
    for entry in valid:
        if str(entry.get("source", "")).lower() == "nvd@nist.gov":
            return entry
    for entry in valid:
        if str(entry.get("type", "")).lower() == "primary":
            return entry
    return valid[0] if valid else None


def _base_score(metrics: Any) -> float | None:
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entry = _pick_metric(metrics.get(key))
        if entry is None:
            continue
        try:
            return float(entry["cvssData"]["baseScore"])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _cwe_ids(weaknesses: Any) -> list[str]:
    found: list[str] = []
    if not isinstance(weaknesses, list):
        return found
    for group in weaknesses:
        if not isinstance(group, dict):
            continue
        for item in group.get("description") or []:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value", "")).strip().upper()
            if _CWE_PATTERN.match(value) and value not in found:
                found.append(value)
    return found


def _cpe_criteria(configurations: Any) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
            return
        if not isinstance(node, dict):
            return
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict):
                continue
            criteria = str(match.get("criteria", "")).strip()
            if criteria and match.get("vulnerable", True) and criteria not in found:
                found.append(criteria)
        walk(node.get("nodes") or [])

    walk(configurations)
    return found


def _reference_urls(references: Any) -> list[str]:
    found: list[str] = []
    if not isinstance(references, list):
        return found
    for item in references:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        if url and url not in found:
            found.append(url)
    return found


def parse_nvd_cve(raw: dict[str, Any]) -> CveRecord:
    """Normalise one NVD record (wrapper or inner ``cve`` object)."""
    inner = raw.get("cve", raw)
    if not isinstance(inner, dict):
        raise TypeError("NVD record must be a JSON object")
    cve_id = str(inner.get("id", "")).strip()
    description = _english(inner.get("descriptions"))
    if not description:
        raise ValueError(f"NVD record {cve_id or '<unknown>'} has no description")
    return CveRecord(
        cve_id=cve_id,
        description=description,
        cvss=_base_score(inner.get("metrics")),
        cwe=_cwe_ids(inner.get("weaknesses")),
        cpe=_cpe_criteria(inner.get("configurations")),
        references=_reference_urls(inner.get("references")),
    )


def parse_nvd_records(
    payload: dict[str, Any],
    include_rejected: bool = False,
) -> list[CveRecord]:
    if not isinstance(payload, dict):
        raise TypeError("NVD snapshot must be a JSON object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise TypeError("NVD snapshot has no 'vulnerabilities' list")
    records: list[CveRecord] = []
    for item in vulnerabilities:
        inner = item.get("cve", item) if isinstance(item, dict) else None
        if not isinstance(inner, dict):
            continue
        status = str(inner.get("vulnStatus", "")).strip().lower()
        if not include_rejected and status == "rejected":
            continue
        records.append(parse_nvd_cve(item))
    return records
