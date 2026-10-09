"""Separate source-line model candidates; never reinterpret normalized object drafts."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.api.contracts import SnapshotBinding
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import PatchDraftAnswer

type Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
MAX_MODEL_PATCH_BYTES = 256 * 1024


class ModelPatchCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["model-patch-capabilities-0.1.0"] = "model-patch-capabilities-0.1.0"
    generation: Literal["configured", "disabled"]
    network_engine: Literal["configured", "disabled"]
    transformer: Literal["configured", "disabled"]
    transformer_sha256: Digest | None = None
    individual_identity_verified: Literal[False] = False
    application_supported: Literal[False] = False

    @field_validator("individual_identity_verified", "application_supported", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("capability flags must be false")
        return value

    @model_validator(mode="after")
    def selected_model(self) -> Self:
        if (self.transformer == "configured") != (self.transformer_sha256 is not None):
            raise ValueError("configured Transformer requires an independent pin")
        return self


def fingerprint(value: BaseModel) -> str:
    return text_sha256(
        json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    )


class GenerateModelPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    patch_id: UUID
    analysis_id: UUID
    finding_id: UUID
    finding_sha256: Digest
    source_sha256: Digest
    baseline_configuration_id: UUID | None = None
    baseline_source_sha256: Digest | None = None
    allow_local_model_context: StrictBool = False

    @model_validator(mode="after")
    def paired_baseline(self) -> Self:
        if (self.baseline_configuration_id is None) != (self.baseline_source_sha256 is None):
            raise ValueError("baseline identity and source pin must be supplied together")
        return self


class ModelPatchIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["model-patch-intent-0.1.0"] = "model-patch-intent-0.1.0"
    request: GenerateModelPatch
    source: SnapshotBinding
    baseline: SnapshotBinding | None = None
    created_at: datetime
    context_sha256: Digest
    knowledge_version: Literal["project-knowledge-0.2.0"]
    knowledge_sha256: Digest
    model_alias_sha256: Digest

    @model_validator(mode="after")
    def bound_request(self) -> Self:
        request = self.request
        if (
            request.allow_local_model_context is not True
            or self.source.source_sha256 != request.source_sha256
            or self.created_at.utcoffset() is None
            or self.created_at < self.source.created_at
            or (self.baseline is None) != (request.baseline_configuration_id is None)
        ):
            raise ValueError("model patch intent binding differs")
        if self.baseline is not None and (
            self.baseline.configuration_id != request.baseline_configuration_id
            or self.baseline.source_sha256 != request.baseline_source_sha256
            or self.baseline.device_id != self.source.device_id
            or self.baseline.created_at > self.source.created_at
            or self.baseline.configuration_id == self.source.configuration_id
        ):
            raise ValueError("model patch baseline binding differs")
        return self


class ModelPatchOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["model-patch-outcome-0.1.0"] = "model-patch-outcome-0.1.0"
    patch_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    status: Literal["draft", "declined", "failed"]
    answer: PatchDraftAnswer | None = Field(default=None, repr=False)
    candidate_sha256: Digest | None = None

    @model_validator(mode="after")
    def bound_outcome(self) -> Self:
        if self.completed_at.utcoffset() is None:
            raise ValueError("model patch outcome requires an aware timestamp")
        if self.status == "failed":
            if self.answer is not None or self.candidate_sha256 is not None:
                raise ValueError("failed attempt cannot retain a rejected answer")
        elif self.answer is None or (
            (self.status == "draft") != (self.answer.patch_draft is not None)
            or (self.status == "draft") != (self.candidate_sha256 is not None)
        ):
            raise ValueError("model patch outcome differs from its answer")
        return self


class ModelPatchProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["source-bound-patch-proposal-0.1.0"] = "source-bound-patch-proposal-0.1.0"
    patch_id: UUID
    analysis_id: UUID
    finding_id: UUID
    finding_sha256: Digest
    source_sha256: Digest
    source: SnapshotBinding
    baseline: SnapshotBinding | None
    created_at: datetime
    completed_at: datetime | None
    status: Literal["generating", "draft", "declined", "failed"]
    context_sha256: Digest
    knowledge_version: Literal["project-knowledge-0.2.0"]
    knowledge_sha256: Digest
    model_alias_sha256: Digest
    proposal_sha256: Digest
    answer: PatchDraftAnswer | None = Field(repr=False)
    candidate_sha256: Digest | None
    generation_attempt_limit: Literal[1] = 1
    formal_verification: Literal["not_run"] = "not_run"
    ml_verification: Literal["not_run"] = "not_run"
    requires_human_review: Literal[True] = True
    model_execution_authenticated: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator(
        "requires_human_review",
        "model_execution_authenticated",
        "approved",
        "applied",
        mode="before",
    )
    @classmethod
    def exact_flags(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("exact boolean flags required")
        return value

    @field_validator("generation_attempt_limit", mode="before")
    @classmethod
    def exact_attempt_limit(cls, value: object) -> int:
        if type(value) is not int or value != 1:
            raise ValueError("one reserved attempt is the limit, not measured inference")
        return value

    @model_validator(mode="after")
    def consistent_public_projection(self) -> Self:
        if (
            self.source_sha256 != self.source.source_sha256
            or self.created_at.utcoffset() is None
            or self.created_at < self.source.created_at
            or (self.status == "generating") != (self.completed_at is None)
        ):
            raise ValueError("model patch projection binding differs")
        if self.completed_at is not None:
            if self.completed_at.utcoffset() is None or self.completed_at < self.created_at:
                raise ValueError("model patch projection timestamps differ")
        if self.status in {"generating", "failed"}:
            if self.answer is not None or self.candidate_sha256 is not None:
                raise ValueError("no accepted candidate for an unfinished or failed attempt")
        elif self.answer is None or (
            (self.status == "draft") != (self.answer.patch_draft is not None)
            or (self.status == "draft") != (self.candidate_sha256 is not None)
        ):
            raise ValueError("model patch projection answer differs")
        return self

    @classmethod
    def from_records(cls, intent: ModelPatchIntent, outcome: ModelPatchOutcome | None) -> Self:
        request = intent.request
        digest = text_sha256(
            json.dumps(
                [
                    intent.model_dump(mode="json"),
                    outcome.model_dump(mode="json") if outcome else None,
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return cls(
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
            context_sha256=intent.context_sha256,
            knowledge_version=intent.knowledge_version,
            knowledge_sha256=intent.knowledge_sha256,
            model_alias_sha256=intent.model_alias_sha256,
            proposal_sha256=digest,
            answer=outcome.answer if outcome else None,
            candidate_sha256=outcome.candidate_sha256 if outcome else None,
        )
