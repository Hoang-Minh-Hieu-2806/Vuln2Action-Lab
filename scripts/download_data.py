"""Opt-in data downloader (Phase 2). Never runs automatically.

TODO(Phase 2): implement NVD/CWE snapshot download with --source/--out flags.
Currently prints guidance only — no network calls, no large downloads.
"""

from __future__ import annotations


def main() -> None:
    print("download_data.py is a Phase-2 stub: no automatic downloads.")
    print("Plan: accept --source nvd|cwe --out data/raw/... and save snapshots.")


if __name__ == "__main__":
    main()
