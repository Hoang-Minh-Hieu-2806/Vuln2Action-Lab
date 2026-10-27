"""Knowledge records used by retrieval and generation."""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CweRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwe_id: str
    name: str = ""
    description: str = ""


class CapecRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capec_id: str
    name: str = ""
    description: str = ""


class ExploitReference(BaseModel):
    """Reference metadata only; executable exploit code is intentionally excluded."""

    model_config = ConfigDict(extra="forbid")
    url: str
    kind: str = "advisory"
    notes: str = ""


class RetrievedContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    text: str
    score: float = Field(default=0.0, ge=0.0)
    backend: str = "keyword"


class KnowledgeDocument(BaseModel):
    """A retrievable document (CWE, CAPEC, or reference metadata)."""

    model_config = ConfigDict(extra="forbid")
    doc_id: str
    text: str
    kind: str = "cwe"
    name: str = ""
    source: str = ""

    @field_validator("doc_id", "text")
    @classmethod
    def must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("knowledge document fields must not be blank")
        return value
