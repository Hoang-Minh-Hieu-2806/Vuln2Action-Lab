"""Load and validate checked-in lab manifests."""

from pathlib import Path

from vuln2action.config import load_yaml
from vuln2action.domain import LabManifest
from vuln2action.utils.filesystem import repo_path


def load_lab_manifest(lab_id: str, labs_root: str | Path | None = None) -> LabManifest:
    root = Path(labs_root) if labs_root else repo_path("labs")
    manifest_path = root / lab_id / "lab.yaml"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Lab manifest not found: {manifest_path}")
    manifest = LabManifest.model_validate(load_yaml(manifest_path))
    if manifest.lab_id != lab_id:
        raise ValueError(f"Manifest lab_id {manifest.lab_id!r} does not match directory {lab_id!r}")
    return manifest
