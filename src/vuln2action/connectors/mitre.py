"""Parsers for CWE and CAPEC XML catalogs (local snapshots only).

Both MITRE catalogs are XML. We accept the catalog as raw ``bytes``/``str`` or
as a path, strip any XML namespace, and normalise IDs to ``CWE-<n>`` /
``CAPEC-<n>`` so they line up with the rest of the domain contracts.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

from vuln2action.domain import CapecRecord, CweRecord

_WHITESPACE = re.compile(r"\s+")


def _read_xml(source: str | bytes | Path) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    text = str(source)
    if text.lstrip().startswith("<"):
        return text.encode("utf-8")
    return Path(text).read_bytes()


def _strip_namespaces(root: ElementTree.Element) -> ElementTree.Element:
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


def _clean(text: str | None) -> str:
    return _WHITESPACE.sub(" ", text or "").strip()


def parse_cwe_xml(source: str | bytes | Path) -> list[CweRecord]:
    """Parse a CWE catalog into deduplicated :class:`CweRecord` items."""
    root = _strip_namespaces(ElementTree.fromstring(_read_xml(source)))
    seen: set[str] = set()
    records: list[CweRecord] = []
    for weakness in root.iter("Weakness"):
        raw_id = (weakness.get("ID") or "").strip()
        if not raw_id:
            continue
        cwe_id = f"CWE-{raw_id}"
        if cwe_id in seen:
            continue
        seen.add(cwe_id)
        records.append(
            CweRecord(
                cwe_id=cwe_id,
                name=(weakness.get("Name") or "").strip(),
                description=_clean(weakness.findtext("Description")),
            )
        )
    return records


def parse_capec_xml(source: str | bytes | Path) -> list[CapecRecord]:
    """Parse a CAPEC catalog into deduplicated :class:`CapecRecord` items."""
    root = _strip_namespaces(ElementTree.fromstring(_read_xml(source)))
    seen: set[str] = set()
    records: list[CapecRecord] = []
    for attack in root.iter("Attack_Pattern"):
        raw_id = (attack.get("ID") or "").strip()
        if not raw_id:
            continue
        capec_id = f"CAPEC-{raw_id}"
        if capec_id in seen:
            continue
        seen.add(capec_id)
        records.append(
            CapecRecord(
                capec_id=capec_id,
                name=(attack.get("Name") or "").strip(),
                description=_clean(attack.findtext("Description")),
            )
        )
    return records
