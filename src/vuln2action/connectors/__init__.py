"""Read-only adapters for local and external vulnerability data."""

from vuln2action.connectors.catalog import lookup_cwe, parse_cpe
from vuln2action.connectors.cve2capec import load_cve2capec
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
from vuln2action.connectors.exploitdb import parse_exploitdb_csv
from vuln2action.connectors.labs import load_lab_manifest
from vuln2action.connectors.mitre import parse_capec_xml, parse_cwe_xml
from vuln2action.connectors.nvd import (
    NvdClient,
    parse_nvd_cve,
    parse_nvd_records,
    save_nvd_snapshot,
)
from vuln2action.connectors.reproduction import (
    allocate_quotas,
    build_candidate_rows,
    build_cve_cwe_pairs,
    build_cwe_capec_pairs,
    build_reference_rows,
    catalog_metadata,
    dataset_stats,
    exploit_rows_for_selected,
    load_nvd_feed,
    load_nvd_feeds,
    make_splits,
    sample_records_by_year,
)
from vuln2action.connectors.reproduction import (
    parse_catalogs as parse_reproduction_catalogs,
)
from vuln2action.connectors.samples import get_sample_cve, load_sample_cves, parse_cve_dict

__all__ = [
    "NvdClient",
    "allocate_quotas",
    "apply_lab_map",
    "build_candidate_rows",
    "build_cve_cwe_pairs",
    "build_cwe_capec_pairs",
    "build_from_snapshots",
    "build_reference_rows",
    "catalog_metadata",
    "dataset_stats",
    "dedupe_cves",
    "exploit_rows_for_selected",
    "get_sample_cve",
    "load_capec_dataset",
    "load_cve2capec",
    "load_cve_dataset",
    "load_cwe_dataset",
    "load_lab_manifest",
    "load_lab_map",
    "load_nvd_feed",
    "load_nvd_feeds",
    "load_sample_cves",
    "lookup_cwe",
    "make_splits",
    "parse_capec_xml",
    "parse_cpe",
    "parse_cve_dict",
    "parse_cwe_xml",
    "parse_exploitdb_csv",
    "parse_nvd_cve",
    "parse_nvd_records",
    "parse_reproduction_catalogs",
    "sample_records_by_year",
    "save_nvd_snapshot",
    "write_capec_dataset",
    "write_cve_dataset",
    "write_cwe_dataset",
]
