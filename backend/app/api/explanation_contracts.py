"""Read-only, snapshot-bound local explanation with retrieved internal sources."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.explanation.knowledge import (
    KNOWLEDGE_VERSION,
    RELEASE_BY_DETECTOR_VERSION,
    DocumentChunk,
    KnowledgeVersion,
)
from app.explanation.local import FindingExplanation
from app.explanation.provider import DraftAnswer


class ExplainFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    analysis_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: Literal["local", "llm"] = "local"
    allow_local_model_context: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def explicit_permission(self) -> "ExplainFinding":
        if self.allow_local_model_context and self.provider != "llm":
            raise ValueError("model context permission requires model selection")
        return self


class ExplanationContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    analysis_id: UUID
    configuration_id: UUID
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    knowledge_version: KnowledgeVersion = KNOWLEDGE_VERSION
    knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval: Literal["explicit_reference"] = "explicit_reference"
    explanation: FindingExplanation
    documents: tuple[DocumentChunk, ...] = Field(min_length=1, max_length=4)
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def bound_explanation(self) -> "ExplanationContext":
        item = self.explanation
        if (
            (item.finding_id, item.device_id, item.source_sha256, item.finding_sha256)
            != (
                self.finding_id,
                self.device_id,
                self.source_sha256,
                self.finding_sha256,
            )
            or len({chunk.citation for chunk in self.documents}) != len(self.documents)
            or (RELEASE_BY_DETECTOR_VERSION.get(item.detector_version) != self.knowledge_version)
        ):
            raise ValueError("explanation or retrieved sources are inconsistent")
        return self


class ExplanationBundle(ExplanationContext):
    version: Literal["finding-context-0.1.0"] = "finding-context-0.1.0"
    provider: Literal["deterministic_local"] = "deterministic_local"
    llm_status: Literal["unavailable"] = "unavailable"


class ModelExplanationBundle(ExplanationContext):
    version: Literal["model-explanation-0.1.0"] = "model-explanation-0.1.0"
    provider: Literal["loopback_language_model"] = "loopback_language_model"
    llm_status: Literal["draft"] = "draft"
    privacy_version: Literal["finding-context-redaction-0.1.0"] = "finding-context-redaction-0.1.0"
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_alias: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    answer: DraftAnswer

    @model_validator(mode="after")
    def bound_citations(self) -> "ModelExplanationBundle":
        if not set(self.answer.citations) <= {chunk.citation for chunk in self.documents}:
            raise ValueError("model answer cites unretrieved sources")
        return self


class ExplanationCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["explanation-capabilities-0.1.0"] = "explanation-capabilities-0.1.0"
    local_model: Literal["disabled", "configured"]
    model_health_checked: Literal[False] = False
    transport: Literal["literal_loopback_only"] = "literal_loopback_only"
    explicit_request_permission_required: Literal[True] = True
