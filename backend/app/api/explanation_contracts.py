"""Read-only, snapshot-bound local explanation with retrieved internal sources."""

from typing import Literal, cast
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from app.explanation.knowledge import (
    KNOWLEDGE_VERSION,
    RELEASE_BY_DETECTOR_VERSION,
    DocumentChunk,
    KnowledgeVersion,
)
from app.explanation.local import FindingExplanation
from app.explanation.provider import DraftAnswer
from app.explanation.retrieval_contracts import SemanticRetrievalContext


class ExplainFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    analysis_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: Literal["local", "llm"] = "local"
    retrieval: Literal["explicit_reference", "semantic_supplement"] = "explicit_reference"
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
    retrieval: Literal["explicit_reference", "semantic_supplement"] = "explicit_reference"
    semantic_retrieval: SemanticRetrievalContext | None = None
    explanation: FindingExplanation
    documents: tuple[DocumentChunk, ...] = Field(min_length=1, max_length=4)
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_serializer(mode="wrap")
    def legacy_wire_shape(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        result = cast(dict[str, object], handler(self))
        if self.semantic_retrieval is None:
            result.pop("semantic_retrieval", None)
        return result

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
        semantic = self.semantic_retrieval
        if (self.retrieval == "semantic_supplement") != (semantic is not None):
            raise ValueError("semantic selection requires bound retrieval metadata")
        if semantic is not None:
            citations = tuple(chunk.citation for chunk in self.documents)
            indexed = {chunk.citation: chunk.content_sha256 for chunk in self.documents}
            extras = tuple(item.citation for item in semantic.matches)
            if (
                len(set(semantic.required_citations)) != len(semantic.required_citations)
                or citations != (*semantic.required_citations, *extras)
                or len(set(extras)) != len(extras)
                or any(
                    not any(
                        required == citation
                        if "#" in citation
                        else required.startswith(f"{citation}#")
                        for required in semantic.required_citations
                    )
                    for citation in item.citations
                )
                or any(
                    indexed.get(item.citation) != item.content_sha256 for item in semantic.matches
                )
            ):
                raise ValueError("required and supplementary citations are inconsistent")
        return self


class ExplanationBundle(ExplanationContext):
    version: Literal["finding-context-0.1.0", "finding-context-0.2.0"] = "finding-context-0.1.0"
    provider: Literal["deterministic_local"] = "deterministic_local"
    llm_status: Literal["unavailable"] = "unavailable"

    @model_validator(mode="after")
    def bound_version(self) -> "ExplanationBundle":
        expected = "finding-context-0.2.0" if self.semantic_retrieval else "finding-context-0.1.0"
        if self.version != expected:
            raise ValueError("incompatible explanation context version")
        return self


class ModelExplanationBundle(ExplanationContext):
    version: Literal["model-explanation-0.1.0", "model-explanation-0.2.0"] = (
        "model-explanation-0.1.0"
    )
    provider: Literal["loopback_language_model"] = "loopback_language_model"
    llm_status: Literal["draft"] = "draft"
    privacy_version: Literal["finding-context-redaction-0.1.0"] = "finding-context-redaction-0.1.0"
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_alias: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    answer: DraftAnswer

    @model_validator(mode="after")
    def bound_citations(self) -> "ModelExplanationBundle":
        expected = (
            "model-explanation-0.2.0" if self.semantic_retrieval else "model-explanation-0.1.0"
        )
        if self.version != expected:
            raise ValueError("incompatible model explanation context version")
        if not set(self.answer.citations) <= {chunk.citation for chunk in self.documents}:
            raise ValueError("model answer cites unretrieved sources")
        return self


class ExplanationCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["explanation-capabilities-0.2.0"] = "explanation-capabilities-0.2.0"
    local_model: Literal["disabled", "configured"]
    model_health_checked: Literal[False] = False
    transport: Literal["literal_loopback_only"] = "literal_loopback_only"
    explicit_request_permission_required: Literal[True] = True
    semantic_retrieval: Literal["disabled", "configured"] = "disabled"
    retrieval_health_checked: Literal[False] = False
