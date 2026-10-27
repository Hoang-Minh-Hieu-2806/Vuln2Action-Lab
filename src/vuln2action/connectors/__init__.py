"""Read-only adapters for local and external vulnerability data."""

from vuln2action.connectors.catalog import lookup_cwe, parse_cpe
from vuln2action.connectors.dataset import (
    apply_lab_map,
    build_from_snapshots,
    dedupe_cves,
    load_capec_dataset,
    load_cve_dataset,
    load_cwe_dataset,
    load_lab_map,
    write_capec_dataset,
    write_cve_dataset,
    write_cwe_dataset,
)
from vuln2action.connectors.labs import load_lab_manifest
from vuln2action.connectors.mitre import parse_capec_xml, parse_cwe_xml
from vuln2action.connectors.nvd import (
    NvdClient,
    parse_nvd_cve,
    parse_nvd_records,
    save_nvd_snapshot,
)
from vuln2action.connectors.samples import get_sample_cve, load_sample_cves, parse_cve_dict

__all__ = [
    "NvdClient",
    "apply_lab_map",
    "build_from_snapshots",
    "dedupe_cves",
    "get_sample_cve",
    "load_capec_dataset",
    "load_cve_dataset",
    "load_cwe_dataset",
    "load_lab_manifest",
    "load_lab_map",
    "load_sample_cves",
    "lookup_cwe",
    "parse_capec_xml",
    "parse_cpe",
    "parse_cve_dict",
    "parse_cwe_xml",
    "parse_nvd_cve",
    "parse_nvd_records",
    "save_nvd_snapshot",
    "write_capec_dataset",
    "write_cve_dataset",
    "write_cwe_dataset",
]
