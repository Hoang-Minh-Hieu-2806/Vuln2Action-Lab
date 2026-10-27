"""Knowledge records used by retrieval and generation."""

from pydantic import BaseModel, ConfigDict, Field


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
