"""Separate saved ordinary-source ML attempts; network history stays network-only."""

import hashlib
import json
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, StrictBool, field_validator, model_validator

from app.api.contracts import SnapshotBinding
from ml.evaluation.contracts import Digest, Frozen
from ml.inference.pair_contracts import ConfigurationPairReport

MAX_SOURCE_ML_BYTES = 4 * 1024 * 1024


def ml_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def source_ml_fingerprint(value: Frozen) -> str:
    return hashlib.sha256(ml_json(value.model_dump(mode="json")).encode()).hexdigest()


class RunSourceMlRecheck(Frozen):
    version: Literal["source-ml-request-0.1.0"] = "source-ml-request-0.1.0"
    recheck_id: UUID
    draft_sha256: Digest
    model_sha256: Digest
    allow_local_model_context: StrictBool = False


class SourceMlMember(SnapshotBinding):
    canonical_sha256: Digest
    total_lines: int = Field(ge=1, le=10000, strict=True)


class SourceMlIntent(Frozen):
    version: Literal["source-ml-intent-0.1.0"] = "source-ml-intent-0.1.0"
    patch_id: UUID
    request: RunSourceMlRecheck
    before: SourceMlMember
    after: SourceMlMember
    created_at: datetime

    @model_validator(mode="after")
    def exact_pair(self) -> Self:
        old, new = self.before, self.after
        if (
            self.created_at.utcoffset() is None
            or not self.request.allow_local_model_context
            or old.device_id != new.device_id
            or old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or not old.created_at <= new.created_at <= self.created_at
        ):
            raise ValueError(
                "ordinary-source ML intent requires an exact existing pair and consent"
            )
        return self


class SourceMlOutcome(Frozen):
    version: Literal["source-ml-outcome-0.1.0"] = "source-ml-outcome-0.1.0"
    recheck_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    execution_status: Literal["completed", "failed"]
    report: ConfigurationPairReport | None = Field(repr=False)
    failure_reason: Literal["worker_failed_or_unavailable"] | None = None

    @model_validator(mode="after")
    def result_state(self) -> Self:
        if (
            self.completed_at.utcoffset() is None
            or ((self.execution_status == "completed") != (self.report is not None))
            or ((self.execution_status == "failed") != (self.failure_reason is not None))
        ):
            raise ValueError("paired ML outcome state differs")
        return self


def source_ml_blockers(outcome: SourceMlOutcome | None) -> tuple[str, ...]:
    result = [
        "formal_verification_not_run",
        "change_specific_ml_quality_not_proven",
        "selected_model_independent_quality_not_proven",
        "baseline_approval_not_proven",
        "individual_engineer_review_required",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
    ]
    if outcome is None:
        result.append("ml_execution_unknown")
    elif outcome.execution_status == "failed":
        result.append("selected_ml_unavailable")
    return tuple(result)


class SourceMlRecheck(Frozen):
    version: Literal["source-ml-recheck-0.1.0"] = "source-ml-recheck-0.1.0"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    model_sha256: Digest
    intent: SourceMlIntent
    outcome: SourceMlOutcome | None = Field(repr=False)
    execution_status: Literal["pending_unknown", "completed", "failed"]
    validation_blockers: tuple[str, ...]
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_ML_BYTES, repr=False)
    review_sha256: Digest
    status: Literal["needs_review"] = "needs_review"
    formal_verification: Literal["not_run"] = "not_run"
    risk_fused: Literal[False] = False
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator(
        "risk_fused", "calibrated", "quality_proven", "approved", "applied", mode="before"
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("experimental ML recheck cannot promote safety or quality")
        return value

    @model_validator(mode="after")
    def exact_records(self) -> Self:
        intent, outcome = self.intent, self.outcome
        if (
            (self.recheck_id, self.patch_id, self.draft_sha256, self.model_sha256)
            != (
                intent.request.recheck_id,
                intent.patch_id,
                intent.request.draft_sha256,
                intent.request.model_sha256,
            )
            or self.execution_status != (outcome.execution_status if outcome else "pending_unknown")
            or self.validation_blockers != source_ml_blockers(outcome)
        ):
            raise ValueError("paired ML projection differs from intent")
        if outcome is not None:
            if (
                outcome.recheck_id != self.recheck_id
                or outcome.intent_sha256 != source_ml_fingerprint(intent)
                or outcome.completed_at < intent.created_at
            ):
                raise ValueError("paired ML outcome belongs to different intent")
            if outcome.report is not None:
                for report, member in (
                    (outcome.report.before, intent.before),
                    (outcome.report.after, intent.after),
                ):
                    if (
                        report.model.model_sha256 != self.model_sha256
                        or report.prediction.raw_source_sha256 != member.source_sha256
                        or report.prediction.total_lines != member.total_lines
                    ):
                        raise ValueError("paired ML report source/model binding differs")
        body = self.model_dump(mode="json", exclude={"review_sha256", "review_json"})
        if (
            self.review_json != ml_json(body)
            or self.review_sha256 != hashlib.sha256(self.review_json.encode()).hexdigest()
        ):
            raise ValueError("paired ML content binding differs")
        return self

    @classmethod
    def from_records(cls, intent: SourceMlIntent, outcome: SourceMlOutcome | None) -> Self:
        body = {
            "version": "source-ml-recheck-0.1.0",
            "recheck_id": str(intent.request.recheck_id),
            "patch_id": str(intent.patch_id),
            "draft_sha256": intent.request.draft_sha256,
            "model_sha256": intent.request.model_sha256,
            "intent": intent.model_dump(mode="json", warnings=False),
            "outcome": outcome.model_dump(mode="json", warnings=False) if outcome else None,
            "execution_status": outcome.execution_status if outcome else "pending_unknown",
            "validation_blockers": source_ml_blockers(outcome),
            "status": "needs_review",
            "formal_verification": "not_run",
            "risk_fused": False,
            "calibrated": False,
            "quality_proven": False,
            "approved": False,
            "applied": False,
        }
        raw = ml_json(body)
        return cls.model_validate(
            body
            | {
                "review_json": raw,
                "review_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            }
        )


class SourceMlSummary(Frozen):
    version: Literal["source-ml-summary-0.1.0"] = "source-ml-summary-0.1.0"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    model_sha256: Digest
    review_sha256: Digest
    created_at: datetime
    completed_at: datetime | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    status: Literal["needs_review"] = "needs_review"

    @classmethod
    def from_recheck(cls, view: SourceMlRecheck) -> Self:
        return cls(
            recheck_id=view.recheck_id,
            patch_id=view.patch_id,
            draft_sha256=view.draft_sha256,
            model_sha256=view.model_sha256,
            review_sha256=view.review_sha256,
            created_at=view.intent.created_at,
            completed_at=view.outcome.completed_at if view.outcome else None,
            execution_status=view.execution_status,
        )


class SourceMlCapabilities(Frozen):
    version: Literal["source-ml-capabilities-0.1.0"] = "source-ml-capabilities-0.1.0"
    inference: Literal["disabled", "configured"]
    model_sha256: Digest | None
    health_checked: Literal[False] = False
    exact_retained_sources_required: Literal[True] = True
    request_consent_required: Literal[True] = True
    formal_verification: Literal["not_run"] = "not_run"

    @field_validator("health_checked", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("configuration does not establish worker health")
        return value

    @model_validator(mode="after")
    def selected_model(self) -> Self:
        if (self.inference == "configured") != (self.model_sha256 is not None):
            raise ValueError("configured paired inference requires an operator pin")
        return self
