"""Provenance sidecar contracts, writer and reader."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vuln2action.utils.filesystem import write_json

NOT_AVAILABLE = "NOT_AVAILABLE"
PROVENANCE_REF = "provenance.json"
SCHEMA_VERSION = 1
_INTEGRITY_KEY = "integrity"
_DIGEST_KEY = "content_sha256"


class ProvenanceError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Integrity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: str = "sha256"
    content_sha256: str


class RetrievalTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: str = NOT_AVAILABLE
    query_fingerprint: str | None = None
    items: list[dict[str, Any]] = Field(default_factory=list)


class GenerationTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = NOT_AVAILABLE
    generation_mode: str = NOT_AVAILABLE
    generator_version: str = NOT_AVAILABLE
    prompt_version: str = NOT_AVAILABLE
    generation_config: dict[str, Any] | None = None
    generation_config_hash: str | None = None
    checkpoint_id: str | None = None
    model_identity: str = NOT_AVAILABLE


class ExecutionTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_mode: str = NOT_AVAILABLE
    selected_action: dict[str, Any] | None = None
    plan_snapshot: dict[str, Any] | None = None
    argv: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    lab_manifest_sha256: str | None = None
    repository_commit: str | None = None
    container_image_digest: str = NOT_AVAILABLE


class EnvironmentTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collected_at: str = NOT_AVAILABLE
    repository_commit: str | None = None
    container_image_digest: str = NOT_AVAILABLE


class ProvenanceDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = SCHEMA_VERSION
    retrieval: RetrievalTrace
    generation: GenerationTrace
    execution: ExecutionTrace
    environment: EnvironmentTrace
    integrity: Integrity | None = None


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def build_provenance(payload: dict[str, Any]) -> ProvenanceDocument:
    evidence = _as_dict(payload.get("evidence"))
    generation = _as_dict(evidence.get("generation"))
    workflow = _as_dict(payload.get("workflow"))
    execution = _as_dict(payload.get("execution"))
    plan = _as_dict(payload.get("plan"))
    generation_input = _as_dict(generation.get("input"))
    backend = generation.get("retrieval_backend")
    backend = backend if isinstance(backend, str) else NOT_AVAILABLE
    items = []
    context_items = generation_input.get("context_items")
    if isinstance(context_items, list):
        for rank, item in enumerate(context_items, start=1):
            if not isinstance(item, dict):
                continue
            source = item.get("source")
            if not isinstance(source, str):
                continue
            score = item.get("score")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                score = NOT_AVAILABLE
            item_backend = item.get("backend")
            if not isinstance(item_backend, str):
                item_backend = NOT_AVAILABLE
            items.append(
                {
                    "rank": rank,
                    "document_id": source,
                    "source": source,
                    "document_kind": NOT_AVAILABLE,
                    "source_url": NOT_AVAILABLE,
                    "retrieval_score": score,
                    "context_backend": item_backend,
                }
            )
    else:
        sources = generation_input.get("context_sources")
        if isinstance(sources, list):
            for rank, source in enumerate(sources, start=1):
                if isinstance(source, str):
                    items.append(
                        {
                            "rank": rank,
                            "document_id": source,
                            "source": source,
                            "document_kind": NOT_AVAILABLE,
                            "source_url": NOT_AVAILABLE,
                            "retrieval_score": NOT_AVAILABLE,
                            "context_backend": NOT_AVAILABLE,
                        }
                    )
    provider = generation.get("provider")
    checkpoint = evidence.get("checkpoint_id")
    if checkpoint is None:
        checkpoint = workflow.get("checkpoint_id")
    if checkpoint is not None and not isinstance(checkpoint, str):
        checkpoint = None
    simulated = execution.get("simulated")
    if isinstance(simulated, bool):
        mode = "simulated" if simulated else "real"
    else:
        mode = NOT_AVAILABLE
    plan_snapshot = None
    if plan:
        steps = plan.get("steps")
        plan_snapshot = {
            "steps": len(steps) if isinstance(steps, list) else 0,
            "lab_id": plan.get("lab_id"),
        }
    return ProvenanceDocument(
        retrieval=RetrievalTrace(backend=backend, query_fingerprint=None, items=items),
        generation=GenerationTrace(
            provider=provider if isinstance(provider, str) else NOT_AVAILABLE,
            generation_mode=provider if isinstance(provider, str) else NOT_AVAILABLE,
            checkpoint_id=checkpoint,
        ),
        execution=ExecutionTrace(execution_mode=mode, plan_snapshot=plan_snapshot),
        environment=EnvironmentTrace(
            collected_at=(
                evidence["collected_at"]
                if isinstance(evidence.get("collected_at"), str)
                else NOT_AVAILABLE
            )
        ),
    )


def write_provenance(run_dir: str | Path, document: ProvenanceDocument) -> Path:
    directory = Path(run_dir)
    directory.mkdir(parents=True, exist_ok=True)
    content = document.model_dump(mode="json")
    content.pop(_INTEGRITY_KEY, None)
    document.integrity = Integrity(content_sha256=_digest(content))
    final_path = directory / PROVENANCE_REF
    return write_json(final_path, document.model_dump(mode="json"))


def _reference(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    generation = _as_dict(_as_dict(payload.get("evidence")).get("generation"))
    reference = generation.get("provenance_ref")
    if reference is None:
        return None
    if not isinstance(reference, str):
        raise ProvenanceError("INVALID_REF", "provenance_ref must be a string")
    return reference


def _resolve_reference(run_dir: str | Path, reference: str) -> Path:
    candidate = Path(reference)
    windows = PureWindowsPath(reference)
    if (
        not reference
        or candidate.is_absolute()
        or candidate.drive
        or windows.drive
        or windows.root
        or ".." in candidate.parts
        or ".." in windows.parts
    ):
        raise ProvenanceError("INVALID_REF", f"Refusing provenance reference: {reference!r}")
    resolved = (Path(run_dir) / candidate).resolve()
    if not resolved.is_relative_to(Path(run_dir).resolve()):
        raise ProvenanceError(
            "INVALID_REF", f"Provenance reference escapes run directory: {reference!r}"
        )
    return resolved


def read_provenance(
    run_dir: str | Path,
    payload: dict[str, Any] | None = None,
) -> ProvenanceDocument | None:
    reference = _reference(payload)
    if reference is None:
        return None
    path = _resolve_reference(run_dir, reference)
    if not path.is_file():
        raise ProvenanceError("MISSING", f"Provenance sidecar not found: {path.name}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProvenanceError("UNREADABLE", f"Cannot read provenance sidecar: {exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("MALFORMED", f"Provenance sidecar is not valid JSON: {exc}") from exc
    try:
        document = ProvenanceDocument.model_validate(data)
    except ValidationError as exc:
        raise ProvenanceError(
            "INVALID_SCHEMA", f"Provenance sidecar schema invalid: {exc}"
        ) from exc
    if document.integrity is None or not document.integrity.content_sha256:
        raise ProvenanceError("MISSING_DIGEST", "Provenance sidecar has no content digest")
    content = document.model_dump(mode="json")
    content.pop(_INTEGRITY_KEY, None)
    if document.integrity.content_sha256 != _digest(content):
        raise ProvenanceError(
            "DIGEST_MISMATCH", "Provenance sidecar digest does not match its content"
        )
    return document
