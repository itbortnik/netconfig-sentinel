"""Distinct persisted policy and wire envelopes; legacy records are not reinterpreted."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import (
    Digest,
    GenerateModelPatch,
    ModelPatchCapabilities,
    ModelPatchIntent,
    ModelPatchOutcome,
    ModelPatchProposal,
    fingerprint,
)
from app.explanation.grounded_patch import (
    RENDERER_VERSION,
    GroundedPatchAnswer,
    GroundedSourceFacts,
)
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import PatchDraftAnswer

LEGACY_PROTOCOL: Literal["legacy-model-patch-0.1.0"] = "legacy-model-patch-0.1.0"
GROUNDED_PROTOCOL: Literal["grounded-model-patch-0.1.0"] = "grounded-model-patch-0.1.0"
type PatchProtocol = Literal["legacy-model-patch-0.1.0", "grounded-model-patch-0.1.0"]


def _digest(value: object) -> str:
    return text_sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    )


def presentation_digest(answer: PatchDraftAnswer) -> str:
    return _digest(answer.model_dump(mode="json", warnings=False))


class GroundedModelPatchIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["grounded-model-patch-intent-0.1.0"] = "grounded-model-patch-intent-0.1.0"
    request: GenerateModelPatch
    source: SnapshotBinding
    baseline: SnapshotBinding | None = None
    created_at: datetime
    context_sha256: Digest
    edit_context_sha256: Digest
    knowledge_version: Literal["project-knowledge-0.2.0"]
    knowledge_sha256: Digest
    model_alias_sha256: Digest
    instructions_sha256: Digest
    answer_schema_sha256: Digest
    source_facts: GroundedSourceFacts = Field(repr=False)
    facts_binding_sha256: Digest
    renderer_version: Literal["grounded-before-presentation-0.1.0"] = RENDERER_VERSION
    renderer_policy_sha256: Digest

    @model_validator(mode="after")
    def bind_inputs(self) -> Self:
        # Share only immutable source/time selection invariants, not old policy replay.
        values = self.model_dump(warnings=False)
        ModelPatchIntent.model_validate(
            {key: values[key] for key in ModelPatchIntent.model_fields if key != "version"}
        )
        facts = GroundedSourceFacts.model_validate(self.source_facts.model_dump(warnings=False))
        if (
            _digest(facts.model_dump(mode="json")) != self.facts_binding_sha256
            or facts.source_sha256 != self.request.source_sha256
            or facts.finding_sha256 != self.request.finding_sha256
            or facts.knowledge_sha256 != self.knowledge_sha256
            or facts.baseline_source_sha256 != self.request.baseline_source_sha256
        ):
            raise ValueError("grounded intent source facts differ")
        return self


class GroundedModelPatchOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["grounded-model-patch-outcome-0.1.0"] = "grounded-model-patch-outcome-0.1.0"
    patch_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    status: Literal["draft", "declined", "failed"]
    # The answer is a deterministic server projection; the typed wire answer is separate.
    answer: PatchDraftAnswer | None = Field(default=None, repr=False)
    model_answer: GroundedPatchAnswer | None = Field(default=None, repr=False)
    projection_sha256: Digest | None = None
    candidate_sha256: Digest | None = None

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        values = self.model_dump(warnings=False)
        ModelPatchOutcome.model_validate(
            {key: values[key] for key in ModelPatchOutcome.model_fields if key != "version"}
        )
        if self.status == "failed":
            if self.model_answer is not None or self.projection_sha256 is not None:
                raise ValueError("failed grounded attempt contains accepted output")
        elif (
            self.model_answer is None
            or self.answer is None
            or (
                self.projection_sha256 != presentation_digest(self.answer)
                or self.model_answer.patch_draft != self.answer.patch_draft
                or self.model_answer.citations != self.answer.citations
            )
        ):
            raise ValueError("grounded outcome differs from model choices or projection")
        return self


type SavedPatchIntent = Annotated[
    ModelPatchIntent | GroundedModelPatchIntent, Field(discriminator="version")
]
type SavedPatchOutcome = Annotated[
    ModelPatchOutcome | GroundedModelPatchOutcome, Field(discriminator="version")
]
INTENT_ADAPTER: TypeAdapter[SavedPatchIntent] = TypeAdapter(SavedPatchIntent)
OUTCOME_ADAPTER: TypeAdapter[SavedPatchOutcome] = TypeAdapter(SavedPatchOutcome)


def protocol_for(intent: ModelPatchIntent | GroundedModelPatchIntent) -> PatchProtocol:
    return GROUNDED_PROTOCOL if isinstance(intent, GroundedModelPatchIntent) else LEGACY_PROTOCOL


def project_grounded_record(
    intent: GroundedModelPatchIntent, outcome: GroundedModelPatchOutcome | None
) -> ModelPatchProposal:
    """Explicit common review view; its SHA binds actual NEW records, not fake legacy ones.

    This view is never returned as a legacy v1 record. Public v2 carries the
    distinct wrapper and server-derived presentation marker alongside it.
    Source-bound replay is the workflow caller's responsibility before exposure.
    """
    request = intent.request
    if outcome is not None and (
        outcome.patch_id != request.patch_id
        or outcome.intent_sha256 != fingerprint(intent)
        or outcome.completed_at < intent.created_at
    ):
        raise ValueError("grounded record pair differs")
    pair = [
        intent.model_dump(mode="json", warnings=False),
        outcome.model_dump(mode="json", warnings=False) if outcome else None,
    ]
    # Match the established whole-record pair fingerprint algorithm, with new record bytes.
    binding = text_sha256(json.dumps(pair, sort_keys=True, separators=(",", ":")))
    return ModelPatchProposal(
        patch_id=request.patch_id,
        analysis_id=request.analysis_id,
        finding_id=request.finding_id,
        finding_sha256=request.finding_sha256,
        source_sha256=request.source_sha256,
        source=intent.source,
        baseline=intent.baseline,
        created_at=intent.created_at,
        completed_at=outcome.completed_at if outcome else None,
        status=outcome.status if outcome else "generating",
        context_sha256=intent.edit_context_sha256,
        knowledge_version=intent.knowledge_version,
        knowledge_sha256=intent.knowledge_sha256,
        model_alias_sha256=intent.model_alias_sha256,
        proposal_sha256=binding,
        answer=outcome.answer if outcome else None,
        candidate_sha256=outcome.candidate_sha256 if outcome else None,
    )


class GroundedModelPatchProposal(BaseModel):
    """Common status/presentation view is explicitly separate from raw model choices."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["grounded-source-bound-patch-proposal-0.1.0"] = (
        "grounded-source-bound-patch-proposal-0.1.0"
    )
    presentation_kind: Literal["server_derived"] = "server_derived"
    projection: ModelPatchProposal
    context_sha256: Digest
    edit_context_sha256: Digest
    source_facts: GroundedSourceFacts = Field(repr=False)
    facts_binding_sha256: Digest
    model_answer: GroundedPatchAnswer | None = Field(repr=False)
    instructions_sha256: Digest
    answer_schema_sha256: Digest
    renderer_version: Literal["grounded-before-presentation-0.1.0"] = RENDERER_VERSION
    renderer_policy_sha256: Digest
    projection_sha256: Digest | None

    @model_validator(mode="after")
    def bind_public_projection(self) -> Self:
        facts = GroundedSourceFacts.model_validate(self.source_facts.model_dump(warnings=False))
        projected = self.projection
        if (
            self.facts_binding_sha256 != _digest(facts.model_dump(mode="json"))
            or self.edit_context_sha256 != projected.context_sha256
            or facts.source_sha256 != projected.source_sha256
            or facts.finding_sha256 != projected.finding_sha256
            or facts.knowledge_sha256 != projected.knowledge_sha256
            or facts.baseline_source_sha256
            != (projected.baseline.source_sha256 if projected.baseline else None)
        ):
            raise ValueError("grounded public source facts differ")
        if projected.status in {"failed", "generating"}:
            if self.model_answer is not None or self.projection_sha256 is not None:
                raise ValueError("no accepted output for incomplete grounded generation")
        elif (
            self.model_answer is None
            or projected.answer is None
            or (
                self.model_answer.facts_binding_sha256 != self.facts_binding_sha256
                or self.model_answer.patch_draft != projected.answer.patch_draft
                or self.model_answer.citations != projected.answer.citations
                or self.projection_sha256 != presentation_digest(projected.answer)
            )
        ):
            raise ValueError("grounded public model/projection binding differs")
        return self

    @classmethod
    def from_records(
        cls, intent: GroundedModelPatchIntent, outcome: GroundedModelPatchOutcome | None
    ) -> Self:
        return cls(
            projection=project_grounded_record(intent, outcome),
            context_sha256=intent.context_sha256,
            edit_context_sha256=intent.edit_context_sha256,
            source_facts=intent.source_facts,
            facts_binding_sha256=intent.facts_binding_sha256,
            model_answer=outcome.model_answer if outcome else None,
            instructions_sha256=intent.instructions_sha256,
            answer_schema_sha256=intent.answer_schema_sha256,
            renderer_version=intent.renderer_version,
            renderer_policy_sha256=intent.renderer_policy_sha256,
            projection_sha256=outcome.projection_sha256 if outcome else None,
        )


type SavedModelPatchProposal = Annotated[
    ModelPatchProposal | GroundedModelPatchProposal, Field(discriminator="version")
]


def common_proposal(
    intent: SavedPatchIntent, outcome: SavedPatchOutcome | None
) -> ModelPatchProposal:
    """Explicit stored-version dispatch; no protocol inference or legacy conversion."""
    if isinstance(intent, GroundedModelPatchIntent):
        if outcome is not None and not isinstance(outcome, GroundedModelPatchOutcome):
            raise ValueError("grounded generation has a different outcome protocol")
        return project_grounded_record(intent, outcome)
    if outcome is not None and not isinstance(outcome, ModelPatchOutcome):
        raise ValueError("legacy generation has a different outcome protocol")
    return ModelPatchProposal.from_records(intent, outcome)


class SavedModelPatchCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["saved-model-patch-capabilities-0.2.0"] = (
        "saved-model-patch-capabilities-0.2.0"
    )
    legacy: ModelPatchCapabilities
    grounded_generation: Literal["configured", "disabled"]
    grounded_protocol: Literal["grounded-model-patch-0.1.0"] = GROUNDED_PROTOCOL
