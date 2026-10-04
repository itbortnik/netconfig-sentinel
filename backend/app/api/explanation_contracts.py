"""Read-only, snapshot-bound local explanation with retrieved internal sources."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.explanation.knowledge import DocumentChunk
from app.explanation.local import FindingExplanation


class ExplainFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    analysis_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: Literal["local", "llm"] = "local"


class ExplanationBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["finding-context-0.1.0"] = "finding-context-0.1.0"
    analysis_id: UUID
    configuration_id: UUID
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    knowledge_version: Literal["project-knowledge-0.1.0"] = "project-knowledge-0.1.0"
    knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval: Literal["explicit_reference"] = "explicit_reference"
    provider: Literal["deterministic_local"] = "deterministic_local"
    llm_status: Literal["unavailable"] = "unavailable"
    explanation: FindingExplanation
    documents: tuple[DocumentChunk, ...] = Field(min_length=1, max_length=4)
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def bound_explanation(self) -> "ExplanationBundle":
        item = self.explanation
        if (item.finding_id, item.device_id, item.source_sha256, item.finding_sha256) != (
            self.finding_id,
            self.device_id,
            self.source_sha256,
            self.finding_sha256,
        ) or len({chunk.citation for chunk in self.documents}) != len(self.documents):
            raise ValueError("explanation or retrieved sources are inconsistent")
        return self
