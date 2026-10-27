"""Normalised vulnerability and product records."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CpeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw: str
    vendor: str = ""
    product: str = ""
    version: str = ""


class CveRecord(BaseModel):
    """Canonical CVE-like input used by the pipeline.

    Demo records are allowed to use non-CVE identifiers, but identifiers and
    descriptions may never be empty.
    """

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    description: str
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    cwe: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    lab_id: str = ""

    @field_validator("cve_id", "description")
    @classmethod
    def must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value
