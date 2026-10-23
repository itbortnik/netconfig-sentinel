"""SDK-aware saved source contracts; legacy records and proofs retain version 0.1."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    TypeAdapter,
    field_validator,
    model_validator,
)

from app.api.source_patch_contracts import (
    MAX_SOURCE_REVIEW_BYTES,
    SelectedSourceCompanion,
    SourcePatchIntent,
    SourcePatchMember,
    SourcePatchOutcome,
    SourcePatchVerification,
    SourcePatchVerificationSummary,
    VerifySourcePatch,
    source_network_digest,
    source_review_fingerprint,
)
from app.verification.batfish import BatfishExecution, BatfishResult, ReachabilityScope
from app.verification.preflight import PreflightReport


class VerifySourcePatchV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["source-patch-request-0.2.0"] = "source-patch-request-0.2.0"
    verification_id: UUID
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    companions: tuple[SelectedSourceCompanion, ...] = Field(default=(), max_length=31)
    scope: ReachabilityScope = Field(repr=False)
    allow_local_engine_upload: StrictBool = False

    @model_validator(mode="after")
    def unique_selection(self) -> Self:
        if len({item.configuration_id for item in self.companions}) != len(self.companions):
            raise ValueError("duplicate companion selection")
        return self


class SourcePatchIntentV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["source-patch-intent-0.2.0"] = "source-patch-intent-0.2.0"
    patch_id: UUID
    request: VerifySourcePatchV2 = Field(repr=False)
    created_at: datetime
    before: SourcePatchMember
    after: SourcePatchMember
    companions: tuple[SourcePatchMember, ...] = Field(default=(), max_length=31, repr=False)
    before_network_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_network_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preflight: PreflightReport = Field(repr=False)

    @model_validator(mode="after")
    def bound_source_pair(self) -> Self:
        old, new = self.before, self.after
        members = (old, new, *self.companions)
        if self.created_at.utcoffset() is None or any(
            row.created_at > self.created_at for row in members
        ):
            raise ValueError("source review requires existing aware inputs")
        if (
            (old.device_id, old.hostname, old.platform)
            != (new.device_id, new.hostname, new.platform)
            or old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or old.created_at > new.created_at
            or self.request.allow_local_engine_upload is not True
        ):
            raise ValueError("source review target binding differs")
        if (
            len({row.device_id for row in (old, *self.companions)}) != 1 + len(self.companions)
            or len({row.hostname.casefold() for row in (old, *self.companions)})
            != 1 + len(self.companions)
            or tuple((row.configuration_id, row.source_sha256) for row in self.companions)
            != tuple((row.configuration_id, row.source_sha256) for row in self.request.companions)
            or self.request.scope.start_node
            not in {row.hostname for row in (old, *self.companions)}
        ):
            raise ValueError("source review companion inventory or scope differs")
        if (
            self.before_network_sha256 != source_network_digest((old, *self.companions))
            or self.after_network_sha256 != source_network_digest((new, *self.companions))
            or self.preflight.device_id != old.device_id
            or self.preflight.reference_id != str(old.configuration_id)
            or self.preflight.before.source_sha256 != old.source_sha256
            or self.preflight.after.source_sha256 != new.source_sha256
            or not self.preflight.before.complete
            or not self.preflight.after.complete
        ):
            raise ValueError("source review preflight or network digest differs")
        return self


class SourcePatchOutcomeV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["source-patch-outcome-0.2.0"] = "source-patch-outcome-0.2.0"
    verification_id: UUID
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime
    network_execution: BatfishExecution = Field(repr=False)

    @property
    def network_result(self) -> BatfishResult:
        return self.network_execution.result

    @model_validator(mode="after")
    def aware_completion(self) -> Self:
        if self.completed_at.utcoffset() is None:
            raise ValueError("source review requires an aware completion")
        return self


def source_validation_blockersV2(
    intent: SourcePatchIntentV2, outcome: SourcePatchOutcomeV2 | None
) -> tuple[str, ...]:
    blocked = [
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
        "selected_ml_not_run",
        "baseline_approval_not_proven",
        "individual_engineer_review_required",
    ]
    result = outcome.network_result if outcome else None
    if result is None:
        blocked.append("network_execution_unknown")
    elif result.status != "no_differences_in_scope":
        blocked.append("formal_scope_not_passed")
    if result is None or result.cleanup_complete is not True:
        blocked.append("engine_cleanup_not_confirmed")
    changes = intent.preflight.policy_changes
    if changes is None or changes.introduced:
        blocked.append("policy_regression_or_missing_comparison")
    return tuple(blocked)


class SourcePatchVerificationV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["source-patch-verification-0.2.0"] = "source-patch-verification-0.2.0"
    verification_id: UUID
    patch_id: UUID
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intent: SourcePatchIntentV2 = Field(repr=False)
    outcome: SourcePatchOutcomeV2 | None = Field(repr=False)
    execution_status: Literal["pending_unknown", "completed"]
    validation_blockers: tuple[str, ...]
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_REVIEW_BYTES, repr=False)
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["needs_review"] = "needs_review"
    ml_status: Literal["not_run"] = "not_run"
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator("approved", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("source review cannot approve or apply a change")
        return value

    @model_validator(mode="after")
    def exact_records(self) -> Self:
        intent, outcome = self.intent, self.outcome
        if (
            (self.verification_id, self.patch_id, self.draft_sha256)
            != (intent.request.verification_id, intent.patch_id, intent.request.draft_sha256)
            or self.execution_status != ("completed" if outcome else "pending_unknown")
            or self.validation_blockers != source_validation_blockersV2(intent, outcome)
        ):
            raise ValueError("source review projection differs from records")
        if outcome is not None and (
            outcome.verification_id != self.verification_id
            or outcome.intent_sha256 != source_review_fingerprint(intent)
            or outcome.completed_at < intent.created_at
            or outcome.network_result.before_sha256 != intent.before_network_sha256
            or outcome.network_result.after_sha256 != intent.after_network_sha256
            or outcome.network_result.scope != intent.request.scope
        ):
            raise ValueError("source review result belongs to different inputs")
        raw = self.model_dump(mode="json", exclude={"review_sha256", "review_json"})
        if self.review_json != json.dumps(raw, sort_keys=True, separators=(",", ":")) or (
            self.review_sha256 != hashlib.sha256(self.review_json.encode()).hexdigest()
        ):
            raise ValueError("source review content binding differs")
        return self

    @classmethod
    def from_records(
        cls, intent: SourcePatchIntentV2, outcome: SourcePatchOutcomeV2 | None
    ) -> Self:
        value = {
            "version": "source-patch-verification-0.2.0",
            "verification_id": str(intent.request.verification_id),
            "patch_id": str(intent.patch_id),
            "draft_sha256": intent.request.draft_sha256,
            "intent": intent.model_dump(mode="json", warnings=False),
            "outcome": outcome.model_dump(mode="json", warnings=False) if outcome else None,
            "execution_status": "completed" if outcome else "pending_unknown",
            "validation_blockers": source_validation_blockersV2(intent, outcome),
            "status": "needs_review",
            "ml_status": "not_run",
            "approved": False,
            "applied": False,
        }
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return cls.model_validate(
            value | {"review_json": raw, "review_sha256": hashlib.sha256(raw.encode()).hexdigest()}
        )


class SourcePatchVerificationSummaryV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["source-patch-verification-summary-0.2.0"] = (
        "source-patch-verification-summary-0.2.0"
    )
    verification_id: UUID
    patch_id: UUID
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    completed_at: datetime | None
    execution_status: Literal["pending_unknown", "completed"]
    network_status: (
        Literal[
            "unavailable",
            "error",
            "incomplete",
            "inconclusive",
            "differences_found",
            "no_differences_in_scope",
        ]
        | None
    )
    cleanup_complete: StrictBool | None
    status: Literal["needs_review"] = "needs_review"

    @classmethod
    def from_verification(cls, view: SourcePatchVerificationV2) -> Self:
        outcome = view.outcome
        return cls(
            verification_id=view.verification_id,
            patch_id=view.patch_id,
            draft_sha256=view.draft_sha256,
            review_sha256=view.review_sha256,
            created_at=view.intent.created_at,
            completed_at=outcome.completed_at if outcome else None,
            execution_status=view.execution_status,
            network_status=outcome.network_result.status if outcome else None,
            cleanup_complete=outcome.network_result.cleanup_complete if outcome else None,
        )


SourcePatchRequest = VerifySourcePatch | VerifySourcePatchV2
SourcePatchIntentRecord = SourcePatchIntent | SourcePatchIntentV2
SourcePatchOutcomeRecord = SourcePatchOutcome | SourcePatchOutcomeV2
SourcePatchReview = SourcePatchVerification | SourcePatchVerificationV2
SourcePatchSummary = SourcePatchVerificationSummary | SourcePatchVerificationSummaryV2
_REQUEST: TypeAdapter[SourcePatchRequest] = TypeAdapter(SourcePatchRequest)
_INTENT: TypeAdapter[SourcePatchIntentRecord] = TypeAdapter(SourcePatchIntentRecord)
_OUTCOME: TypeAdapter[SourcePatchOutcomeRecord] = TypeAdapter(SourcePatchOutcomeRecord)
_REVIEW: TypeAdapter[SourcePatchReview] = TypeAdapter(
    Annotated[SourcePatchReview, Field(discriminator="version")]
)


def parse_source_patch_request(value: object) -> SourcePatchRequest:
    # An omitted request version retains the original HTTP protocol.
    return _REQUEST.validate_python(value)


def parse_source_patch_intent_json(value: str) -> SourcePatchIntentRecord:
    return _INTENT.validate_json(value)


def parse_source_patch_outcome_json(value: str) -> SourcePatchOutcomeRecord:
    return _OUTCOME.validate_json(value)


def source_patch_view(
    intent: SourcePatchIntentRecord, outcome: SourcePatchOutcomeRecord | None
) -> SourcePatchReview:
    if isinstance(intent, SourcePatchIntentV2):
        if outcome is not None and not isinstance(outcome, SourcePatchOutcomeV2):
            raise ValueError("source review record protocols differ")
        return SourcePatchVerificationV2.from_records(intent, outcome)
    if outcome is not None and not isinstance(outcome, SourcePatchOutcome):
        raise ValueError("source review record protocols differ")
    return SourcePatchVerification.from_records(intent, outcome)


def source_patch_summary(view: SourcePatchReview) -> SourcePatchSummary:
    if isinstance(view, SourcePatchVerificationV2):
        return SourcePatchVerificationSummaryV2.from_verification(view)
    return SourcePatchVerificationSummary.from_verification(view)


def parse_source_patch_review(value: object) -> SourcePatchReview:
    if isinstance(value, BaseModel):
        value = value.model_dump(warnings=False)
    return _REVIEW.validate_python(value)
