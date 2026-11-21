"""Parsers for CWE and CAPEC XML catalogs (local snapshots only).

Both MITRE catalogs are XML. We accept the catalog as raw ``bytes``/``str`` or
as a path, strip any XML namespace, and normalise IDs to ``CWE-<n>`` /
``CAPEC-<n>`` so they line up with the rest of the domain contracts.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

from vuln2action.domain import CapecRecord, CapecStep, CweRecord

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


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _related_ids(parent: ElementTree.Element | None, tag: str, attr: str, prefix: str) -> list[str]:
    if parent is None:
        return []
    return _dedupe(
        [
            f"{prefix}-{value}"
            for node in parent.iter(tag)
            if (value := (node.get(attr) or "").strip())
        ]
    )


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
        parent_ids = _dedupe(
            [
                f"CWE-{(related.get('CWE_ID') or '').strip()}"
                for related in weakness.findall("Related_Weaknesses/Related_Weakness")
                if (related.get("Nature") or "").strip() == "ChildOf"
                and (related.get("CWE_ID") or "").strip()
            ]
        )
        records.append(
            CweRecord(
                cwe_id=cwe_id,
                name=(weakness.get("Name") or "").strip(),
                description=_clean(weakness.findtext("Description")),
                parent_ids=parent_ids,
                related_capec_ids=_related_ids(
                    weakness.find("Related_Attack_Patterns"),
                    "Related_Attack_Pattern",
                    "CAPEC_ID",
                    "CAPEC",
                ),
            )
        )
    return records


def _parse_execution_flow(attack: ElementTree.Element) -> list[CapecStep]:
    steps: list[CapecStep] = []
    for index, node in enumerate(attack.findall("Execution_Flow/Attack_Step"), start=1):
        raw_step = (node.findtext("Step") or "").strip()
        try:
            step_number = int(raw_step)
        except ValueError:
            step_number = index
        steps.append(
            CapecStep(
                step=max(1, step_number),
                phase=_clean(node.findtext("Phase")),
                description=_clean(node.findtext("Description")),
                techniques=_dedupe(
                    [_clean(technique.text) for technique in node.findall("Technique")]
                ),
            )
        )
    return steps


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
        parent_ids = [
            f"CAPEC-{(node.get('CAPEC_ID') or '').strip()}"
            for node in attack.findall("Related_Attack_Patterns/Related_Attack_Pattern")
            if (node.get("Nature") or "").strip() == "ChildOf"
            and (node.get("CAPEC_ID") or "").strip()
        ]
        records.append(
            CapecRecord(
                capec_id=capec_id,
                name=(attack.get("Name") or "").strip(),
                description=_clean(attack.findtext("Description")),
                abstraction=(attack.get("Abstraction") or "").strip(),
                parent_ids=_dedupe(parent_ids),
                related_cwe_ids=_related_ids(
                    attack.find("Related_Weaknesses"),
                    "Related_Weakness",
                    "CWE_ID",
                    "CWE",
                ),
                execution_flow=_parse_execution_flow(attack),
            )
        )
    return records
