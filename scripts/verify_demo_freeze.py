from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_DEFAULT_REL = Path("artifacts/demo/final-cve001-20261123T065251Z")
_REQUIRED = (
    Path("consistency.json"),
    Path("hashes/SHA256SUMS.txt"),
    Path("evidence/report.json"),
    Path("evidence/provenance.json"),
    Path("evidence/report.md"),
    Path("logs/cli-exit.txt"),
    Path("logs/cli-stdout.log"),
    Path("validator/validation.json"),
    Path("screenshots/cli-console.png"),
    Path("screenshots/report-md.png"),
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify(artifact_dir: Path) -> tuple[list[str], int]:
    errors: list[str] = []
    for rel in _REQUIRED:
        if not (artifact_dir / rel).is_file():
            errors.append(f"missing required file: {rel}")

    if errors:
        return errors, 0

    root = artifact_dir.resolve()
    sums_path = artifact_dir / "hashes/SHA256SUMS.txt"
    entries = 0
    for raw_line in sums_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^([0-9a-f]{64})\s+(.+)$", line)
        if match is None:
            errors.append(f"invalid SHA256SUMS line: {line}")
            continue
        expected, rel_text = match.group(1), match.group(2)
        rel = Path(rel_text)
        resolved = (artifact_dir / rel).resolve()
        if resolved != root and root not in resolved.parents:
            errors.append(f"hash path escapes artifact dir: {rel}")
            continue
        target = artifact_dir / rel
        if not target.is_file():
            errors.append(f"missing hash target: {rel}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            errors.append(f"hash mismatch: {rel}")
        entries += 1

    consistency = _load_json(artifact_dir / "consistency.json")
    if consistency.get("all_pass") is not True:
        errors.append("consistency.all_pass is not true")

    report = _load_json(artifact_dir / "evidence/report.json")
    result = report.get("result") or {}
    if result.get("status") != "SIMULATED":
        errors.append("report.result.status is not SIMULATED")
    if report.get("provider") != "rule_based":
        errors.append("report.provider is not rule_based")
    execution = report.get("execution") or {}
    if execution.get("simulated") is not True:
        errors.append("report.execution.simulated is not true")

    validation = _load_json(artifact_dir / "validator/validation.json")
    if validation.get("status") != "SIMULATED":
        errors.append("validator.status is not SIMULATED")

    return errors, entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the frozen CVE-001 demo artifact.")
    parser.add_argument("--artifact-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    artifact_dir = args.artifact_dir or (Path(__file__).resolve().parents[1] / _DEFAULT_REL)

    errors, entries = verify(artifact_dir)
    if errors:
        print("DEMO FREEZE VERDICT: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    print("DEMO FREEZE VERDICT: PASS")
    print(f"artifact_dir: {str(artifact_dir)!a}")
    print("expected_output:")
    print("  provider=rule_based")
    print("  status=SIMULATED")
    print("  execution.simulated=true")
    print("  consistency.all_pass=true")
    print(f"  sha256_entries={entries} verified")
    print("limitations:")
    print("  - No Docker validation; SIMULATED verdict only")
    print("  - No T5-generated flow or checkpoint in this demo")
    print("  - GUI reference flow is CAPEC metadata, not generated output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
