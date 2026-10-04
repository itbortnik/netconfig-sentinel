"""Immutable normalized change drafts and local-only review; never executable patches."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.api.contracts import SnapshotBinding
from app.api.diff_contracts import SnapshotDiff
from app.patching.review import local_validation_blockers
from app.verification.preflight import PreflightReport

MAX_RECORD_BYTES = 4 * 1024 * 1024


def draft_fingerprint(diff: SnapshotDiff) -> str:
    contents = json.dumps(
        ["snapshot-patch-draft-0.1.0", diff.model_dump(mode="json")],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(contents.encode("utf-8")).hexdigest()


class CreatePatchDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    patch_id: UUID
    before_configuration_id: UUID
    after_configuration_id: UUID
    before_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def different_inputs(self) -> CreatePatchDraft:
        if self.before_configuration_id == self.after_configuration_id or (
            self.before_source_sha256 == self.after_source_sha256
        ):
            raise ValueError("draft requires different source snapshots")
        return self


class PatchDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["snapshot-patch-draft-0.1.0"] = "snapshot-patch-draft-0.1.0"
    patch_id: UUID
    created_at: datetime
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["draft"] = "draft"
    representation: Literal["normalized_objects"] = "normalized_objects"
    diff: SnapshotDiff
    requires_human_review: Literal[True] = True

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("draft requires a timezone")
        return value

    @model_validator(mode="after")
    def bound_draft(self) -> PatchDraft:
        if (
            not self.diff.source_changed
            or not self.diff.changes
            or (
                self.draft_sha256 != draft_fingerprint(self.diff)
                or self.created_at < self.diff.after.created_at
            )
        ):
            raise ValueError("draft is empty or its binding differs")
        return self

    def intent(self) -> CreatePatchDraft:
        return CreatePatchDraft(
            patch_id=self.patch_id,
            before_configuration_id=self.diff.before.configuration_id,
            after_configuration_id=self.diff.after.configuration_id,
            before_source_sha256=self.diff.before.source_sha256,
            after_source_sha256=self.diff.after.source_sha256,
        )


class PatchSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["snapshot-patch-summary-0.1.0"] = "snapshot-patch-summary-0.1.0"
    patch_id: UUID
    created_at: datetime
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["draft"] = "draft"
    before: SnapshotBinding
    after: SnapshotBinding
    coverage: Literal["supported_complete", "partial"]
    change_count: int = Field(ge=1, le=500)

    @classmethod
    def from_draft(cls, draft: PatchDraft) -> PatchSummary:
        return cls(
            patch_id=draft.patch_id,
            created_at=draft.created_at,
            draft_sha256=draft.draft_sha256,
            before=SnapshotBinding.model_validate(
                draft.diff.before.model_dump(
                    include={
                        "configuration_id",
                        "device_id",
                        "source_sha256",
                        "created_at",
                    }
                )
            ),
            after=SnapshotBinding.model_validate(
                draft.diff.after.model_dump(
                    include={
                        "configuration_id",
                        "device_id",
                        "source_sha256",
                        "created_at",
                    }
                )
            ),
            coverage=draft.diff.coverage,
            change_count=len(draft.diff.changes),
        )


class VerifyPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    verification_id: UUID
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: Literal["local_preflight", "batfish"] = "local_preflight"


class VerificationRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["snapshot-patch-review-0.1.0"] = "snapshot-patch-review-0.1.0"
    verification_id: UUID
    patch_id: UUID
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    kind: Literal["local_preflight"] = "local_preflight"
    status: Literal["needs_review"] = "needs_review"
    before: SnapshotBinding
    after: SnapshotBinding
    preflight: PreflightReport
    validation_blockers: tuple[str, ...]

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("review requires a timezone")
        return value

    @model_validator(mode="after")
    def bound_review(self) -> VerificationRun:
        report = self.preflight
        if (
            self.before.configuration_id == self.after.configuration_id
            or self.before.device_id != self.after.device_id
            or self.before.created_at > self.after.created_at
            or self.created_at < self.after.created_at
            or report.device_id != self.after.device_id
            or report.reference_id != str(self.before.configuration_id)
            or (report.before.source_sha256, report.after.source_sha256)
            != (self.before.source_sha256, self.after.source_sha256)
            or self.validation_blockers != local_validation_blockers(report)
        ):
            raise ValueError("review does not belong to the selected snapshots")
        return self


class VerificationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["snapshot-patch-review-summary-0.1.0"] = "snapshot-patch-review-summary-0.1.0"
    verification_id: UUID
    patch_id: UUID
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    kind: Literal["local_preflight"] = "local_preflight"
    status: Literal["needs_review"] = "needs_review"
    policy_catalog_version: str
    before_complete: bool
    after_complete: bool
    current_policy_finding_count: int = Field(ge=0)
    introduced_count: int | None = Field(ge=0)
    resolved_count: int | None = Field(ge=0)
    formal_verification: Literal["not_run"] = "not_run"

    @classmethod
    def from_run(cls, run: VerificationRun) -> VerificationSummary:
        report = run.preflight
        changes = report.policy_changes
        return cls(
            verification_id=run.verification_id,
            patch_id=run.patch_id,
            draft_sha256=run.draft_sha256,
            created_at=run.created_at,
            policy_catalog_version=report.policy_catalog_version,
            before_complete=report.before.complete,
            after_complete=report.after.complete,
            current_policy_finding_count=len(report.after_policy_findings),
            introduced_count=len(changes.introduced) if changes is not None else None,
            resolved_count=len(changes.resolved) if changes is not None else None,
        )
