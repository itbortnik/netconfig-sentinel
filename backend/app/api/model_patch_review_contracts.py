"""Immutable verification attempts and explicit service-role review decisions."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import Digest
from app.core.permissions import Role
from app.explanation.knowledge import text_sha256
from app.patching.candidate_review import CandidateReviewReport
from app.verification.batfish import ReachabilityScope


class SelectedConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    configuration_id: UUID
    source_sha256: Digest


class VerifySavedModelPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    verification_id: UUID
    proposal_sha256: Digest
    mode: Literal["local_preflight", "batfish"] = "local_preflight"
    network: tuple[SelectedConfiguration, ...] = Field(min_length=1, max_length=32)
    scope: ReachabilityScope = Field(repr=False)
    allow_local_engine_upload: StrictBool = False
    transformer_sha256: Digest | None = None
    allow_local_model_context: StrictBool = False

    @model_validator(mode="after")
    def unique_selection(self) -> Self:
        if len({item.configuration_id for item in self.network}) != len(self.network):
            raise ValueError("duplicate selected configuration")
        if self.mode != "batfish" and self.allow_local_engine_upload:
            raise ValueError("engine consent requires engine selection")
        if self.transformer_sha256 is None and self.allow_local_model_context:
            raise ValueError("model consent requires model selection")
        return self


class SavedPatchReviewIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["saved-patch-review-intent-0.1.0"] = "saved-patch-review-intent-0.1.0"
    patch_id: UUID
    request: VerifySavedModelPatch
    created_at: datetime
    network: tuple[SnapshotBinding, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def bind_selection(self) -> Self:
        if (
            self.created_at.utcoffset() is None
            or (
                tuple((row.configuration_id, row.source_sha256) for row in self.network)
                != tuple((row.configuration_id, row.source_sha256) for row in self.request.network)
            )
            or len({row.device_id for row in self.network}) != len(self.network)
        ):
            raise ValueError("review intent network binding differs")
        if any(row.created_at > self.created_at for row in self.network):
            raise ValueError("future review input")
        return self


class StatisticalRecheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    model_id: UUID
    artifact_sha256: Digest
    before_score_samples: float
    after_score_samples: float
    before_decision_function: float
    after_decision_function: float
    before_prediction: Literal[-1, 1]
    after_prediction: Literal[-1, 1]
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False

    @field_validator("before_prediction", "after_prediction", mode="before")
    @classmethod
    def exact_prediction(cls, value: Any) -> int:
        if type(value) is not int or value not in {-1, 1}:
            raise ValueError("prediction must be -1 or 1")
        return value

    @field_validator("calibrated", "quality_proven", mode="before")
    @classmethod
    def exact_false(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("unqualified statistical flags must be false")
        return value


class SavedPatchReviewOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["saved-patch-review-outcome-0.1.0"] = "saved-patch-review-outcome-0.1.0"
    verification_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    execution_status: Literal["completed", "failed"]
    report: CandidateReviewReport | None = Field(default=None, repr=False)
    ml_execution: Literal["not_requested", "completed", "unavailable"] = "not_requested"
    statistical_recheck: StatisticalRecheck | None = None

    @model_validator(mode="after")
    def bind_execution(self) -> Self:
        if self.completed_at.utcoffset() is None or (
            (self.execution_status == "completed") != (self.report is not None)
        ):
            raise ValueError("review execution result differs")
        if self.execution_status == "failed" and (
            self.statistical_recheck is not None or self.ml_execution == "completed"
        ):
            raise ValueError("failed review cannot claim completed checks")
        return self


def approval_blockers(report: CandidateReviewReport | None, ml_execution: str) -> tuple[str, ...]:
    if report is None:
        return ("verification_not_completed",)
    blocked = []
    network = report.network_result
    if network is None or network.batfish.status != "no_differences_in_scope":
        blocked.append("formal_scope_not_passed")
    if network is None or network.batfish.cleanup_complete is not True:
        blocked.append("engine_cleanup_not_confirmed")
    local = report.local_review.preflight
    if not local.before.complete or not local.after.complete:
        blocked.append("incomplete_parsing")
    if local.policy_changes is None or local.policy_changes.introduced:
        blocked.append("policy_regression_or_missing_comparison")
    if (
        ml_execution != "completed"
        or not report.ml_reviews
        or any(row.transformer.status != "completed" for row in report.ml_reviews)
    ):
        blocked.append("selected_ml_not_completed")
    if "ml_selected_category_not_supported" in report.missing_checks:
        blocked.append("selected_ml_category_not_supported")
    return tuple(blocked)


class SavedPatchVerificationFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["saved-model-patch-review-0.1.0"] = "saved-model-patch-review-0.1.0"
    verification_id: UUID
    patch_id: UUID
    proposal_sha256: Digest
    created_at: datetime
    completed_at: datetime | None
    request: VerifySavedModelPatch = Field(repr=False)
    network: tuple[SnapshotBinding, ...]
    execution_status: Literal["running", "completed", "failed"]
    report: CandidateReviewReport | None = Field(repr=False)
    ml_execution: Literal["not_requested", "completed", "unavailable"]
    statistical_recheck: StatisticalRecheck | None
    approval_blockers: tuple[str, ...]
    status: Literal["needs_review"] = "needs_review"
    applied: Literal[False] = False
    topology_pinned_at_generation: Literal[False] = False

    @field_validator("applied", "topology_pinned_at_generation", mode="before")
    @classmethod
    def exact_false(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("review flags must be false")
        return value

    @model_validator(mode="after")
    def execution_state(self) -> Self:
        if self.created_at.utcoffset() is None:
            raise ValueError("aware review timestamp required")
        if self.execution_status == "running":
            if (
                self.completed_at is not None
                or self.report is not None
                or (self.statistical_recheck is not None or self.ml_execution != "not_requested")
            ):
                raise ValueError("running review cannot claim completed checks")
        elif (
            self.completed_at is None
            or self.completed_at.utcoffset() is None
            or (self.completed_at < self.created_at)
            or ((self.execution_status == "completed") != (self.report is not None))
        ):
            raise ValueError("review result state differs")
        SavedPatchReviewIntent(
            patch_id=self.patch_id,
            request=self.request,
            created_at=self.created_at,
            network=self.network,
        )
        if self.execution_status == "failed" and (
            self.statistical_recheck is not None or self.ml_execution == "completed"
        ):
            raise ValueError("failed review cannot claim completed checks")
        if self.report is not None:
            if (self.request.mode == "batfish") != (self.report.network_result is not None) or (
                (self.request.transformer_sha256 is None) != (self.ml_execution == "not_requested")
            ):
                raise ValueError("selected checks differ from supplied results")
            if self.report.scope != self.request.scope or (
                self.ml_execution == "completed"
            ) != bool(
                self.report.ml_reviews
                and all(row.transformer.status == "completed" for row in self.report.ml_reviews)
            ):
                raise ValueError("review selection/execution differs")
            if self.report.expected_model_sha256s != (
                (self.request.transformer_sha256,) if self.report.ml_reviews else ()
            ):
                raise ValueError("review model selection differs")
        return self


class SavedPatchVerification(SavedPatchVerificationFacts):
    review_sha256: Digest

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        content = self.model_dump(mode="json", exclude={"review_sha256"})
        if (
            self.review_sha256
            != text_sha256(json.dumps(content, sort_keys=True, separators=(",", ":")))
            or self.approval_blockers != approval_blockers(self.report, self.ml_execution)
            or self.proposal_sha256 != self.request.proposal_sha256
            or self.verification_id != self.request.verification_id
        ):
            raise ValueError("review projection content binding differs")
        return self

    @classmethod
    def from_records(
        cls, intent: SavedPatchReviewIntent, outcome: SavedPatchReviewOutcome | None
    ) -> Self:
        values = {
            "version": "saved-model-patch-review-0.1.0",
            "verification_id": intent.request.verification_id,
            "patch_id": intent.patch_id,
            "proposal_sha256": intent.request.proposal_sha256,
            "created_at": intent.created_at,
            "completed_at": outcome.completed_at if outcome else None,
            "request": intent.request,
            "network": intent.network,
            "execution_status": outcome.execution_status if outcome else "running",
            "report": outcome.report if outcome else None,
            "ml_execution": outcome.ml_execution if outcome else "not_requested",
            "statistical_recheck": outcome.statistical_recheck if outcome else None,
            "approval_blockers": approval_blockers(
                outcome.report if outcome else None,
                outcome.ml_execution if outcome else "not_requested",
            ),
            "status": "needs_review",
            "applied": False,
            "topology_pinned_at_generation": False,
        }
        # Serialize dates/UUIDs through a typed record before hashing the public projection.
        temporary = SavedPatchVerificationFacts.model_validate(values)
        digest = text_sha256(
            json.dumps(
                temporary.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return cls.model_validate({**values, "review_sha256": digest})


class ReviewSavedModelPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    decision_id: UUID
    verification_id: UUID
    proposal_sha256: Digest
    review_sha256: Digest
    verdict: Literal["approved", "rejected", "needs_more_information"]
    comment: str = Field(min_length=1, max_length=1200, repr=False)
    acknowledged_limitations: tuple[str, ...] = Field(default=(), max_length=64)
    device_syntax_checked: StrictBool = False
    management_access_checked: StrictBool = False
    rollback_ready: StrictBool = False

    @field_validator("comment")
    @classmethod
    def bounded_comment(cls, value: str) -> str:
        if not value.strip() or any(
            not char.isprintable() and char not in "\n\t" for char in value
        ):
            raise ValueError("invalid review comment")
        return value

    @field_validator("acknowledged_limitations")
    @classmethod
    def unique_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(
            not item or len(item) > 100 or not item.isascii() for item in value
        ):
            raise ValueError("invalid limitation acknowledgements")
        return value


class SavedPatchDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["saved-model-patch-decision-0.1.0"] = "saved-model-patch-decision-0.1.0"
    patch_id: UUID
    request: ReviewSavedModelPatch = Field(repr=False)
    created_at: datetime
    service_role: Role
    individual_identity_verified: Literal[False] = False
    applied: Literal[False] = False

    @field_validator("individual_identity_verified", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("decision flags must be false")
        return value

    @model_validator(mode="after")
    def engineer_service_role(self) -> Self:
        if self.created_at.utcoffset() is None or self.service_role not in {"engineer", "admin"}:
            raise ValueError("engineer service role and aware timestamp required")
        return self


def validate_decision(decision: SavedPatchDecision, run: SavedPatchVerification) -> None:
    selected = decision.request
    if (
        decision.patch_id != run.patch_id
        or selected.verification_id != run.verification_id
        or selected.proposal_sha256 != run.proposal_sha256
        or selected.review_sha256 != run.review_sha256
        or run.execution_status == "running"
        or run.completed_at is None
        or decision.created_at < run.completed_at
    ):
        raise ValueError("decision selection differs or verification is unfinished")
    limitations = set(run.report.missing_checks) if run.report else set()
    if not set(selected.acknowledged_limitations).issubset(limitations):
        raise ValueError("unknown limitation acknowledgement")
    if selected.verdict == "approved" and (
        run.approval_blockers
        or set(selected.acknowledged_limitations) != limitations
        or not selected.device_syntax_checked
        or not selected.management_access_checked
        or not selected.rollback_ready
    ):
        raise ValueError("approval requires actual selected checks and explicit attestations")
