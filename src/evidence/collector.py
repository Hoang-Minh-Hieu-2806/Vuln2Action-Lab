"""Evidence collector: gather artefacts for a run (placeholder)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class EvidenceCollector:
    """Collect command output, HTTP metadata, logs, timestamps, verdicts."""

    def __init__(self) -> None:
        self.items: dict[str, Any] = {"collected_at": datetime.now(timezone.utc).isoformat()}

    def add_command_output(self, step_id: str, output: str) -> None:
        self.items.setdefault("command_outputs", {})[step_id] = output

    def add_http_metadata(self, url: str, status: int, notes: str = "") -> None:
        self.items.setdefault("http", []).append({"url": url, "status": status, "notes": notes})

    def add_log(self, message: str) -> None:
        self.items.setdefault("logs", []).append(message)

    def add_result(self, result: object) -> None:
        to_dict = getattr(result, "to_dict", None)
        self.items["validation_result"] = to_dict() if callable(to_dict) else str(result)

    def bundle(self) -> dict[str, Any]:
        return dict(self.items)
