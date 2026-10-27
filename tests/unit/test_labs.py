"""Lab manifests are explicit and agree with sample metadata."""

from vuln2action.connectors import load_lab_manifest, load_sample_cves


def test_every_sample_has_matching_manifest():
    manifests = {cve.cve_id: load_lab_manifest(cve.lab_id) for cve in load_sample_cves()}
    for cve_id, manifest in manifests.items():
        assert manifest.vulnerability_id == cve_id


def test_live_lab_declares_counterfactual_and_commands():
    manifest = load_lab_manifest("cve-001")
    assert manifest.status == "ready"
    assert manifest.has_patched_counterfactual is True
    assert manifest.setup_command
    assert manifest.validation_command
    assert manifest.teardown_command


def test_remaining_labs_stay_placeholders():
    for lab_id in ("cve-002", "cve-003"):
        manifest = load_lab_manifest(lab_id)
        assert manifest.status == "placeholder"
        assert manifest.has_patched_counterfactual is False
        assert manifest.validation_command == []
