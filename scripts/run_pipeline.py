"""Source-checkout wrapper for the installed CLI entry point."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _entry in (_ROOT, _ROOT / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from vuln2action.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
