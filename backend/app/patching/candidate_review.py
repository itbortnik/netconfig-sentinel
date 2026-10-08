"""Unified confidential candidate facts, never model/engine authority or approval."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain.fingerprints import finding_fingerprint
from app.explanation.patch_provider import GeneratedModelPatch, PreparedPatchPrompt
from app.patching.review import PatchReview
from app.verification.batfish import ReachabilityScope
from app.verification.model_patch import ModelPatchBatfishReport, prepare_model_patch_snapshots
from app.verification.snapshots import NetworkSnapshot
from ml.inference.change_contracts import MLChangeReview

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CandidateReviewUnavailable(ValueError):
    """Constant failure without candidate, model answer, input identities or paths."""


def _missing_checks(
    local_review: PatchReview,
    network_result: ModelPatchBatfishReport | None,
    ml_reviews: tuple[MLChangeReview, ...],
    selected_category: str,
) -> tuple[str, ...]:
    missing = [
        "human_review_required",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
        "operational_topology_not_verified",
        "execution_not_authenticated_by_report",
        "baseline_approval_not_established",
        "explicit_scope_not_full_network_qualification",
        "ml_quality_not_qualified",
    ]
    if local_review.preflight.after_policy_findings:
        missing.append("current_policy_findings")
    if network_result is None:
        missing.append("formal_report_not_supplied")
    else:
        network = network_result.batfish
        if network.status in {"unavailable", "error", "incomplete"}:
            missing.append("formal_query_not_completed")
        elif network.status == "inconclusive":
            missing.append("empty_formal_scope")
        elif network.status == "differences_found":
            missing.append("reachability_differences_unreviewed")
        if network.cleanup_complete is not True:
            missing.append("network_cleanup_unconfirmed")
    if not ml_reviews or all(row.transformer.status == "not_selected" for row in ml_reviews):
        missing.append("ml_model_not_selected")
    if any(row.transformer.status == "unavailable" for row in ml_reviews):
        missing.append("ml_unavailable")
    if any(
        row.transformer.status == "completed"
        and row.transformer.before is not None
        and selected_category.removeprefix("management.")
        not in (row.transformer.before.category_scores or {})
        for row in ml_reviews
    ):
        missing.append("ml_selected_category_not_supported")
    return tuple(missing)


class CandidateReviewReport(BaseModel):
    """Consistency of supplied facts, not an authenticated execution certificate."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["candidate-review-0.1.0"] = "candidate-review-0.1.0"
    device_id: UUID
    source_sha256: Digest
    candidate_sha256: Digest
    finding_sha256: Digest
    context_sha256: Digest
    selected_category: Literal["management.telnet_enabled", "management.ssh_version_1"]
    before_snapshot_sha256: Digest
    after_snapshot_sha256: Digest
    scope: ReachabilityScope = Field(repr=False)
    local_review: PatchReview = Field(repr=False)
    network_result: ModelPatchBatfishReport | None = Field(default=None, repr=False)
    ml_reviews: tuple[MLChangeReview, ...] = Field(default=(), max_length=4, repr=False)
    expected_model_sha256s: tuple[Digest | None, ...] = Field(default=(), max_length=4)
    missing_checks: tuple[str, ...] = ()
    status: Literal["needs_review"] = "needs_review"
    requires_human_review: Literal[True] = True
    approved: Literal[False] = False
    applied: Literal[False] = False
    execution_authenticated: Literal[False] = False
    semantic_truth_proven: Literal[False] = False
    confidential: Literal[True] = True

    @field_validator(
        "requires_human_review",
        "approved",
        "applied",
        "execution_authenticated",
        "semantic_truth_proven",
        "confidential",
        mode="before",
    )
    @classmethod
    def exact_flags(cls, value: Any) -> bool:
        if type(value) is not bool:
            raise ValueError("review flags must be booleans")
        return value

    @model_validator(mode="after")
    def bound_checks(self) -> Self:
        proposal = self.local_review.proposal
        if (
            proposal.device_id != self.device_id
            or proposal.before_sha256 != self.source_sha256
            or proposal.after_sha256 != self.candidate_sha256
        ):
            raise ValueError("local review source binding differs")
        if self.network_result is not None:
            network = self.network_result
            if (
                network.device_id,
                network.source_sha256,
                network.candidate_sha256,
                network.finding_sha256,
                network.context_sha256,
            ) != (
                self.device_id,
                self.source_sha256,
                self.candidate_sha256,
                self.finding_sha256,
                self.context_sha256,
            ) or (
                network.batfish.before_sha256,
                network.batfish.after_sha256,
                network.batfish.scope,
            ) != (self.before_snapshot_sha256, self.after_snapshot_sha256, self.scope):
                raise ValueError("network review binding differs")
        if len(self.ml_reviews) != len(self.expected_model_sha256s):
            raise ValueError("each supplied ML review requires an independent selection pin")
        selected = [pin for pin in self.expected_model_sha256s if pin is not None]
        if len(selected) != len(set(selected)):
            raise ValueError("duplicate model selections")
        for row, pin in zip(self.ml_reviews, self.expected_model_sha256s, strict=True):
            if row.local_review != self.local_review or row.transformer.model_sha256 != pin:
                raise ValueError("ML source or selected model binding differs")
            if (pin is None) != (row.transformer.status == "not_selected"):
                raise ValueError("unselected model has no identity pin")
        if self.missing_checks != _missing_checks(
            self.local_review, self.network_result, self.ml_reviews, self.selected_category
        ):
            raise ValueError("missing checks do not match supplied evidence")
        return self


def build_candidate_review(
    generated: GeneratedModelPatch,
    *,
    prepared: PreparedPatchPrompt,
    before: NetworkSnapshot,
    scope: ReachabilityScope,
    network_result: ModelPatchBatfishReport | None = None,
    ml_reviews: tuple[MLChangeReview, ...] = (),
    expected_model_sha256s: tuple[str | None, ...] = (),
) -> CandidateReviewReport:
    """Fresh source replay and declared-report consistency; no inference/upload/write.

    Independent pins select supplied models, but do not authenticate their execution.
    An absent result remains absent; historical local formal_not_run is preserved.
    """
    try:
        pair = prepare_model_patch_snapshots(generated, prepared=prepared, before=before)
        assert generated.metadata is not None
        scope = ReachabilityScope.model_validate(scope.model_dump())
        if scope.start_node not in {item.hostname for item in before.configs}:
            raise ValueError("scope start node is absent")
        if type(ml_reviews) is not tuple or type(expected_model_sha256s) is not tuple:
            raise ValueError("review selections must be tuples")
        if len(ml_reviews) > 4 or len(expected_model_sha256s) > 4:
            raise ValueError("too many review selections")
        if any(
            pin is not None and (type(pin) is not str or re.fullmatch(r"[0-9a-f]{64}", pin) is None)
            for pin in expected_model_sha256s
        ):
            raise ValueError("unsupported independent model pin")
        local = PatchReview.model_validate(generated.metadata.review.model_dump())
        network = (
            ModelPatchBatfishReport.model_validate(network_result.model_dump())
            if network_result is not None
            else None
        )
        models = tuple(MLChangeReview.model_validate(row.model_dump()) for row in ml_reviews)
        data = {
            "device_id": pair.device_id,
            "source_sha256": prepared.source_sha256,
            "candidate_sha256": generated.metadata.review.proposal.after_sha256,
            "finding_sha256": finding_fingerprint(prepared.finding),
            "context_sha256": prepared.prompt.context_sha256,
            "selected_category": prepared.finding.category,
            "before_snapshot_sha256": pair.before.digest,
            "after_snapshot_sha256": pair.after.digest,
            "scope": scope.model_dump(),
            "local_review": local.model_dump(),
            "network_result": network.model_dump() if network is not None else None,
            "ml_reviews": tuple(row.model_dump() for row in models),
            "expected_model_sha256s": expected_model_sha256s,
        }
        data["missing_checks"] = _missing_checks(local, network, models, prepared.finding.category)
        return CandidateReviewReport.model_validate(data)
    except Exception:
        raise CandidateReviewUnavailable("Candidate review is unavailable.") from None
