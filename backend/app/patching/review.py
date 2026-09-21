"""Bind a draft to local preflight evidence without allowing formal promotion."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from app.parsers import parse_configuration
from app.patching.proposal import PatchProposal, check_proposal_inputs
from app.verification.preflight import PreflightReport, review_configuration_change


def _blockers(report: PreflightReport) -> tuple[str, ...]:
    blockers = ["formal_verification_not_run", "human_review_required"]
    if not report.before.complete or not report.after.complete:
        blockers.append("incomplete_parsing")
    if report.reference_status != "completed":
        blockers.append("reference_comparison_unavailable")
    if report.after_policy_findings:
        blockers.append("current_policy_findings")
    if report.policy_changes is not None and report.policy_changes.introduced:
        blockers.append("introduced_policy_findings")
    return tuple(blockers)


class PatchReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["patch-review-0.1.0"] = "patch-review-0.1.0"
    proposal: PatchProposal
    preflight: PreflightReport
    status: Literal["needs_review"] = "needs_review"
    validation_blockers: tuple[str, ...]

    @model_validator(mode="after")
    def bound_evidence(self) -> PatchReview:
        if (
            self.proposal.device_id != self.preflight.device_id
            or self.proposal.reference_id != self.preflight.reference_id
            or self.proposal.before_sha256 != self.preflight.before.source_sha256
            or self.proposal.after_sha256 != self.preflight.after.source_sha256
        ):
            raise ValueError("preflight does not belong to this proposal")
        if self.validation_blockers != _blockers(self.preflight):
            raise ValueError("validation blockers do not match the available checks")
        return self


def review_patch_proposal(
    proposal: PatchProposal, before: str, after: str, *, device_id: UUID
) -> PatchReview:
    check_proposal_inputs(proposal, before, after, device_id=device_id)
    report = review_configuration_change(
        parse_configuration(before, filename="before.cfg"),
        parse_configuration(after, filename="after.cfg"),
        device_id=device_id,
        reference_id=proposal.reference_id,
    )
    return PatchReview(proposal=proposal, preflight=report, validation_blockers=_blockers(report))
