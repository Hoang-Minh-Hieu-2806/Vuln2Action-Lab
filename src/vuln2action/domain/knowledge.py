"""Knowledge records used by retrieval and generation."""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CweRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwe_id: str
    name: str = ""
    description: str = ""
    parent_ids: list[str] = Field(default_factory=list)
    related_capec_ids: list[str] = Field(default_factory=list)


class CapecStep(BaseModel):
    """One step of a CAPEC execution flow (Explore/Experiment/Exploit)."""

    model_config = ConfigDict(extra="forbid")
    step: int = Field(ge=1)
    phase: str = ""
    description: str = ""
    techniques: list[str] = Field(default_factory=list)


class CapecRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capec_id: str
    name: str = ""
    description: str = ""
    abstraction: str = ""
    parent_ids: list[str] = Field(default_factory=list)
    related_cwe_ids: list[str] = Field(default_factory=list)
    execution_flow: list[CapecStep] = Field(default_factory=list)


class ExploitRecord(BaseModel):
    """ExploitDB metadata; executable code is intentionally not stored."""

    model_config = ConfigDict(extra="forbid")
    exploit_id: str
    description: str
    file_path: str = ""
    code_url: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    type: str = ""
    platform: str = ""
    date_published: str = ""
    verified: bool = False
    tags: list[str] = Field(default_factory=list)


class CveCapecReference(BaseModel):
    """External CVE->CWE/CAPEC reference used for evaluation, not training."""

    model_config = ConfigDict(extra="forbid")
    cve_id: str
    cwe_ids: list[str] = Field(default_factory=list)
    capec_ids: list[str] = Field(default_factory=list)
    source: str = "CVE2CAPEC"


class CapecPrediction(BaseModel):
    """One best-CAPEC prediction for a CVE, with evaluation-only labels."""

    model_config = ConfigDict(extra="forbid")
    cve_id: str
    method: str
    selected_capec_id: str | None = None
    score: float = 0.0
    candidate_capec_ids: list[str] = Field(default_factory=list)
    reference_capec_ids: list[str] = Field(default_factory=list)
    correct: bool | None = None


class CapecSelectionMetrics(BaseModel):
    """Top-1 and candidate-recall metrics for one selector and split."""

    model_config = ConfigDict(extra="forbid")
    method: str
    split: str
    cves: int
    with_candidates: int
    with_reference: int
    evaluated: int
    correct: int
    accuracy: float
    accuracy_answered: float
    candidate_recall: float
    mean_score: float


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
