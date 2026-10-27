"""Lab manifests are explicit and agree with sample metadata."""

from vuln2action.connectors import load_lab_manifest, load_sample_cves


def test_every_sample_has_matching_manifest():
    for cve in load_sample_cves():
        manifest = load_lab_manifest(cve.lab_id)
        assert manifest.vulnerability_id == cve.cve_id
        assert manifest.status == "placeholder"
        assert manifest.has_patched_counterfactual is False
