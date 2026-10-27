"""Small offline catalog adapters used by the baseline."""

from vuln2action.domain import CpeRecord, CweRecord


_KNOWN_CWES: dict[str, CweRecord] = {
    "CWE-79": CweRecord(
        cwe_id="CWE-79",
        name="Cross-site Scripting (XSS)",
        description="Improper neutralisation of input during web page generation.",
    ),
    "CWE-89": CweRecord(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="Improper neutralisation of special elements used in an SQL command.",
    ),
    "CWE-22": CweRecord(
        cwe_id="CWE-22",
        name="Path Traversal",
        description="Improper limitation of a pathname to a restricted directory.",
    ),
}


def lookup_cwe(cwe_id: str) -> CweRecord | None:
    return _KNOWN_CWES.get(cwe_id)


def parse_cpe(raw: str) -> CpeRecord:
    parts = raw.split(":")
    return CpeRecord(
        raw=raw,
        vendor=parts[3] if len(parts) > 3 else "",
        product=parts[4] if len(parts) > 4 else "",
        version=parts[5] if len(parts) > 5 else "",
    )
