"""CPE (affected product) records.

TODO(Phase 2): parse CPE strings/dictionaries into structured CpeRecord.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CpeRecord:
    """Minimal CPE entry (kept as raw string + parsed vendor/product)."""

    raw: str
    vendor: str = ""
    product: str = ""
    version: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"raw": self.raw, "vendor": self.vendor, "product": self.product, "version": self.version}


def parse_cpe(raw: str) -> CpeRecord:
    """Best-effort parse of a cpe:2.3 URI string (never raises)."""
    # TODO(Phase 2): use the official CPE dictionary format properly.
    try:
        parts = raw.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""
        return CpeRecord(raw=raw, vendor=vendor, product=product, version=version)
    except Exception:
        return CpeRecord(raw=raw)
