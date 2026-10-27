"""Source-checkout wrapper for the installed CLI entry point."""

from vuln2action.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
