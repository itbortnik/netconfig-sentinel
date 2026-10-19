"""Separate ordinary-draft frozen Forest records; no reinterpretation of other reviews."""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, StrictBool, field_validator, model_validator

from app.api.contracts import ModelSummary, SnapshotBinding, StatisticalContext
from app.api.model_patch_review_contracts import StatisticalRecheck
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from ml.evaluation.contracts import Digest, Frozen

MAX_SOURCE_FOREST_BYTES = 4 * 1024 * 1024


class RunSourceForestRecheck(Frozen):
    version: Literal["source-forest-request-0.1.0"] = "source-forest-request-0.1.0"
    recheck_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    model_id: UUID
    artifact_sha256: Digest
    allow_local_model_context: StrictBool = False


class SourceForestMember(SnapshotBinding):
    canonical_sha256: Digest


class SourceForestSelection(Frozen):
    version: Literal["source-forest-selection-0.1.0"] = "source-forest-selection-0.1.0"
    patch_id: UUID
    draft_sha256: Digest
    before: SnapshotBinding
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    before_analysis_created_at: datetime
    original: StatisticalContext

    @model_validator(mode="after")
    def chronology(self) -> Self:
        if (
            self.before_analysis_created_at.utcoffset() is None
            or self.before_analysis_created_at < self.before.created_at
            or self.original.model.created_at > self.before_analysis_created_at
        ):
            raise ValueError("original statistical selection chronology differs")
        return self


class SourceForestIntent(Frozen):
    version: Literal["source-forest-intent-0.1.0"] = "source-forest-intent-0.1.0"
    patch_id: UUID
    request: RunSourceForestRecheck
    before: SourceForestMember
    after: SourceForestMember
    selection: SourceForestSelection
    created_at: datetime

    @model_validator(mode="after")
    def bindings(self) -> Self:
        selected, request = self.selection, self.request
        if (
            self.created_at.utcoffset() is None
            or self.created_at < self.after.created_at
            or self.created_at < selected.before_analysis_created_at
            or self.before.created_at > self.after.created_at
            or self.before.device_id != self.after.device_id
            or self.before.configuration_id == self.after.configuration_id
            or self.before.source_sha256 == self.after.source_sha256
            or request.allow_local_model_context is not True
            or self.patch_id != selected.patch_id
            or request.draft_sha256 != selected.draft_sha256
            or request.before_analysis_id != selected.before_analysis_id
            or request.before_analysis_sha256 != selected.before_analysis_sha256
            or request.model_id != selected.original.model.model_id
            or request.artifact_sha256 != selected.original.model.artifact_sha256
            or self.before.model_dump(exclude={"canonical_sha256"}) != selected.before.model_dump()
        ):
            raise ValueError("ordinary original statistical intent differs")
        return self


class SourceForestReport(Frozen):
    version: Literal["source-forest-report-0.1.0"] = "source-forest-report-0.1.0"
    model: ModelSummary
    scores: StatisticalRecheck
    interpretation: Literal["experimental_scores_not_change_validation"] = (
        "experimental_scores_not_change_validation"
    )

    @model_validator(mode="after")
    def numeric_binding(self) -> Self:
        scores = self.scores
        if (scores.model_id, scores.artifact_sha256) != (
            self.model.model_id,
            self.model.artifact_sha256,
        ):
            raise ValueError("statistical result model differs")
        for score, decision, prediction in (
            (
                scores.before_score_samples,
                scores.before_decision_function,
                scores.before_prediction,
            ),
            (scores.after_score_samples, scores.after_decision_function, scores.after_prediction),
        ):
            if (
                not -1 <= score <= 0
                or not -1 <= decision <= 1
                or decision != score - self.model.decision_offset
                or prediction != (-1 if decision < 0 else 1)
            ):
                raise ValueError("statistical result threshold or score differs")
        return self


class SourceForestOutcome(Frozen):
    version: Literal["source-forest-outcome-0.1.0"] = "source-forest-outcome-0.1.0"
    recheck_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    execution_status: Literal["completed", "failed"]
    report: SourceForestReport | None = None
    failure_reason: Literal["original_baseline_or_numeric_result_unavailable"] | None = None

    @model_validator(mode="after")
    def state(self) -> Self:
        if (
            self.completed_at.utcoffset() is None
            or (self.execution_status == "completed") != (self.report is not None)
            or (self.execution_status == "failed") != (self.failure_reason is not None)
        ):
            raise ValueError("statistical outcome state differs")
        return self


def forest_blockers(outcome: SourceForestOutcome | None) -> tuple[str, ...]:
    result = (
        "formal_verification_not_run",
        "original_statistical_quality_not_proven",
        "all_original_detectors_not_rerun",
        "baseline_approval_not_proven",
        "individual_engineer_review_required",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
    )
    if outcome is None:
        return (*result, "statistical_execution_unknown")
    if outcome.execution_status == "failed":
        return (*result, "original_statistical_unavailable")
    return result


class SourceForestRecheck(Frozen):
    version: Literal["source-forest-recheck-0.1.0"] = "source-forest-recheck-0.1.0"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    model_id: UUID
    artifact_sha256: Digest
    intent: SourceForestIntent
    outcome: SourceForestOutcome | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    validation_blockers: tuple[str, ...]
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_FOREST_BYTES)
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
            raise ValueError("unqualified statistical review flags must remain false")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        from hashlib import sha256

        intent, outcome, request = self.intent, self.outcome, self.intent.request
        if (
            (
                self.recheck_id,
                self.patch_id,
                self.draft_sha256,
                self.before_analysis_id,
                self.before_analysis_sha256,
                self.model_id,
                self.artifact_sha256,
            )
            != (
                request.recheck_id,
                intent.patch_id,
                request.draft_sha256,
                request.before_analysis_id,
                request.before_analysis_sha256,
                request.model_id,
                request.artifact_sha256,
            )
            or self.execution_status != (outcome.execution_status if outcome else "pending_unknown")
            or self.validation_blockers != forest_blockers(outcome)
        ):
            raise ValueError("statistical review projection differs")
        if outcome is not None:
            if (
                outcome.recheck_id != self.recheck_id
                or outcome.intent_sha256 != source_ml_fingerprint(intent)
                or outcome.completed_at < intent.created_at
            ):
                raise ValueError("statistical outcome intent differs")
            if outcome.report is not None:
                report, original = outcome.report, intent.selection.original
                if report.model != original.model or (
                    report.scores.before_score_samples,
                    report.scores.before_decision_function,
                    report.scores.before_prediction,
                ) != (original.score_samples, original.decision_function, original.prediction):
                    raise ValueError("statistical result original baseline differs")
        expected = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            self.review_json != expected
            or self.review_sha256 != sha256(expected.encode()).hexdigest()
        ):
            raise ValueError("statistical review proof differs")
        return self

    @classmethod
    def from_records(cls, intent: SourceForestIntent, outcome: SourceForestOutcome | None) -> Self:
        from hashlib import sha256

        request = intent.request
        fields = {
            "version": "source-forest-recheck-0.1.0",
            "recheck_id": str(request.recheck_id),
            "patch_id": str(intent.patch_id),
            "draft_sha256": request.draft_sha256,
            "before_analysis_id": str(request.before_analysis_id),
            "before_analysis_sha256": request.before_analysis_sha256,
            "model_id": str(request.model_id),
            "artifact_sha256": request.artifact_sha256,
            "intent": intent.model_dump(mode="json"),
            "outcome": outcome.model_dump(mode="json") if outcome else None,
            "execution_status": outcome.execution_status if outcome else "pending_unknown",
            "validation_blockers": list(forest_blockers(outcome)),
            "status": "needs_review",
            "formal_verification": "not_run",
            "risk_fused": False,
            "calibrated": False,
            "quality_proven": False,
            "approved": False,
            "applied": False,
        }
        proof = ml_json(fields)
        return cls.model_validate(
            fields | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}
        )


class SourceForestSummary(Frozen):
    version: Literal["source-forest-summary-0.1.0"] = "source-forest-summary-0.1.0"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    model_id: UUID
    artifact_sha256: Digest
    review_sha256: Digest
    created_at: datetime
    completed_at: datetime | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    status: Literal["needs_review"] = "needs_review"

    @classmethod
    def from_recheck(cls, value: SourceForestRecheck) -> Self:
        return cls.model_validate(
            value.model_dump(
                mode="json",
                include={
                    "recheck_id",
                    "patch_id",
                    "draft_sha256",
                    "before_analysis_id",
                    "model_id",
                    "artifact_sha256",
                    "review_sha256",
                    "execution_status",
                    "status",
                },
            )
            | {
                "created_at": value.intent.created_at,
                "completed_at": value.outcome.completed_at if value.outcome else None,
            }
        )
