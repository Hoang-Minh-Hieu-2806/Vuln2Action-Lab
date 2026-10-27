"""Read-only adapters for local and external vulnerability data."""

from vuln2action.connectors.catalog import lookup_cwe, parse_cpe
from vuln2action.connectors.labs import load_lab_manifest
from vuln2action.connectors.samples import get_sample_cve, load_sample_cves, parse_cve_dict

__all__ = [
    "get_sample_cve",
    "load_lab_manifest",
    "load_sample_cves",
    "lookup_cwe",
    "parse_cpe",
    "parse_cve_dict",
]
