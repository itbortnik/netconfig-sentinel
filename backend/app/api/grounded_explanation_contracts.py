"""Opt-in ordinary explanation envelope; legacy prose contracts remain unchanged."""

from __future__ import annotations

import json
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.api.explanation_contracts import ExplanationCapabilities, ExplanationContext
from app.explanation.grounded_explanation import (
    RENDERER_VERSION,
    GroundedExplanationAnswer,
    GroundedExplanationFacts,
    GroundedExplanationPresentation,
    GroundedExplanationProtocol,
    grounded_prompt_for_facts,
    render_grounded_explanation,
    renderer_policy_sha256,
)
from app.explanation.knowledge import load_knowledge_catalog, text_sha256


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


class GroundedExplanationBundle(ExplanationContext):
    version: GroundedExplanationProtocol = "grounded-model-explanation-0.2.0"
    provider: Literal["loopback_grounded_language_model"] = "loopback_grounded_language_model"
    llm_status: Literal["draft"] = "draft"
    presentation_kind: Literal["server_derived"] = "server_derived"
    privacy_version: Literal["finding-context-redaction-0.1.0"] = "finding-context-redaction-0.1.0"
    model_alias: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # These exact UTF-8 JSON strings, not a consumer's float serialization, are normative.
    source_facts_json: str = Field(max_length=65536, repr=False)
    facts_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_answer: GroundedExplanationAnswer = Field(repr=False)
    model_answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    instructions_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    renderer_version: Literal["grounded-explanation-presentation-0.1.0"] = RENDERER_VERSION
    renderer_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection_json: str = Field(max_length=131072, repr=False)
    projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def source_facts(self) -> GroundedExplanationFacts:
        return GroundedExplanationFacts.model_validate_json(self.source_facts_json)

    @property
    def presentation(self) -> GroundedExplanationPresentation:
        return GroundedExplanationPresentation.model_validate_json(self.projection_json)

    @model_validator(mode="after")
    def exact_projection(self) -> Self:
        facts, presentation = self.source_facts, self.presentation
        answer = GroundedExplanationAnswer.model_validate(
            self.model_answer.model_dump(warnings=False)
        )
        canonical_facts = _canonical(facts.model_dump(mode="json", warnings=False))
        canonical_presentation = _canonical(presentation.model_dump(mode="json", warnings=False))
        expected = render_grounded_explanation(answer, facts)
        if (
            self.source_facts_json != canonical_facts
            or self.facts_binding_sha256 != text_sha256(self.source_facts_json)
            or self.projection_json != canonical_presentation
            or self.projection_sha256 != text_sha256(self.projection_json)
            or self.projection_json != _canonical(expected.model_dump(mode="json", warnings=False))
            or self.model_answer_sha256
            != text_sha256(_canonical(answer.model_dump(mode="json", warnings=False)))
            or facts.source_sha256 != self.source_sha256
            or facts.finding_sha256 != self.finding_sha256
            or facts.detector_version != self.explanation.detector_version
            or facts.knowledge_version != self.knowledge_version
            or facts.knowledge_sha256 != self.knowledge_sha256
        ):
            raise ValueError("grounded explanation source or projection differs")
        catalog = load_knowledge_catalog(self.knowledge_version)
        indexed = {chunk.citation: chunk for chunk in catalog.chunks}
        required = (
            self.semantic_retrieval.required_citations
            if self.semantic_retrieval
            else tuple(chunk.citation for chunk in self.documents)
        )
        if self.knowledge_sha256 != catalog.sha256 or (
            len(facts.documents) != len(self.documents)
            or any(
                chunk.citation not in indexed
                or _canonical(chunk.model_dump(mode="json", warnings=False))
                != _canonical(indexed[chunk.citation].model_dump(mode="json", warnings=False))
                or (pin.citation, pin.document_sha256, pin.content_sha256, pin.role)
                != (
                    chunk.citation,
                    chunk.document_sha256,
                    chunk.content_sha256,
                    "required" if chunk.citation in required else "supplement",
                )
                for chunk, pin in zip(self.documents, facts.documents, strict=False)
            )
        ):
            raise ValueError("grounded explanation document bindings differ")
        prompt = grounded_prompt_for_facts(facts, self.documents, protocol=self.version)
        if (
            self.context_sha256 != prompt.context_sha256
            or self.instructions_sha256 != text_sha256(prompt.instructions)
            or self.answer_schema_sha256 != text_sha256(prompt.answer_schema_json)
            or self.renderer_policy_sha256 != renderer_policy_sha256()
        ):
            raise ValueError("grounded explanation protocol bindings differ")
        return self


class GroundedExplanationCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[
        "grounded-explanation-capabilities-0.1.0", "grounded-explanation-capabilities-0.2.0"
    ] = "grounded-explanation-capabilities-0.2.0"
    legacy: ExplanationCapabilities
    grounded_explanation: Literal["disabled", "configured"]
    protocol: GroundedExplanationProtocol = "grounded-model-explanation-0.2.0"
    model_health_checked: Literal[False] = False
    explicit_request_permission_required: Literal[True] = True

    @model_validator(mode="after")
    def known_protocol_pair(self) -> Self:
        if self.version.removeprefix("grounded-explanation-capabilities-") != (
            self.protocol.removeprefix("grounded-model-explanation-")
        ):
            raise ValueError("grounded explanation capability protocol differs")
        return self
