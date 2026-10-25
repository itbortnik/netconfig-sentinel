"""Suppressed aggregate over explicit partial policy observations, without historical reruns."""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.api.patch_contracts import PatchDraft
from app.api.source_evidence_contracts import SourceEvidenceMember
from app.api.source_evidence_partial_contracts import (
    SourceEvidenceReportV5,
    validate_source_evidence_report,
)
from app.api.source_partial_contracts import PartialMode, SourcePartialDiagnostic, _DiagnosticFrozen
from app.detection.fusion.source_scope_priority import (
    _WEIGHTS,
    PRIORITY_SOURCES,
    SOURCE_PRIORITY_LIMITATIONS,
    FindingPriorityObservation,
    PriorityGuardrail,
    PrioritySource,
    _findings,
)
from ml.evaluation.contracts import Digest, UnitScore

type ZeroWeight = Annotated[float, Field(strict=True, ge=0, le=0)]
PARTIAL_PRIORITY_LIMITATIONS = (
    *SOURCE_PRIORITY_LIMITATIONS,
    "Only the selected original-catalog policy diagnostics were computed in this mode.",
    "Incomplete parsing suppresses every aggregate weight and contribution, including "
    "when the after snapshot alone is complete. The aggregate and band remain unavailable.",
    "Visible after findings and applicable critical-policy guards do not classify paired "
    "changes or establish repair, completeness or overall safety.",
)


class PartialPriorityEvidenceRef(_DiagnosticFrozen):
    kind: Literal["deterministic"] = "deterministic"
    version: Literal["source-deterministic-recheck-0.2.0"]
    record_id: UUID
    review_sha256: Digest


class SourcePartialPriorityComponent(_DiagnosticFrozen):
    source: PrioritySource
    status: Literal["completed", "unavailable"]
    reason: Literal["finding_priority", "not_selected"]
    evidence: PartialPriorityEvidenceRef | None
    observation: FindingPriorityObservation | None
    raw_score: UnitScore | None
    configured_weight: UnitScore
    effective_weight: ZeroWeight
    contribution: None

    @model_validator(mode="after")
    def diagnostic_observation(self) -> Self:
        if self.configured_weight != _WEIGHTS[self.source]:
            raise ValueError("partial component configured weight differs from profile0.1")
        if self.source == "policy":
            if self.evidence is None or self.observation is None:
                raise ValueError("partial policy component requires its saved observation")
            PartialPriorityEvidenceRef.model_validate(self.evidence.model_dump(warnings=False))
            observed = FindingPriorityObservation.model_validate(
                self.observation.model_dump(warnings=False)
            )
            if (
                observed.detector != "policy_engine"
                or self.status != "completed"
                or self.reason != "finding_priority"
                or self.raw_score != observed.priority_score
            ):
                raise ValueError("partial policy component differs from its finding observation")
        elif (
            self.status != "unavailable"
            or self.reason != "not_selected"
            or self.evidence is not None
            or self.observation is not None
            or self.raw_score is not None
        ):
            raise ValueError("unselected partial component cannot imply a completed healthy zero")
        return self


class SourcePriorityCompositionV3(_DiagnosticFrozen):
    version: Literal["source-priority-composition-0.3.0"] = "source-priority-composition-0.3.0"
    profile_version: Literal["source-priority-profile-0.1.0"] = "source-priority-profile-0.1.0"
    mode: PartialMode = "policy_only_partial_diagnostic"
    side: Literal["after"] = "after"
    report_id: UUID
    report_sha256: Digest
    report_version: Literal["source-evidence-report-0.5.0"]
    patch_id: UUID
    draft_sha256: Digest
    before: SourceEvidenceMember
    after: SourceEvidenceMember
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    selected_evidence: tuple[PartialPriorityEvidenceRef] = Field(min_length=1, max_length=1)
    coverage: Literal["partial"] = "partial"
    candidate_parser_confidence: UnitScore
    components: tuple[SourcePartialPriorityComponent, ...] = Field(min_length=5, max_length=5)
    availability_mask: tuple[Literal["policy"]] = ("policy",)
    status: Literal["unavailable"] = "unavailable"
    score: None
    band: None
    applicable_guardrails: tuple[PriorityGuardrail, ...] = Field(max_length=1)
    applied_guardrails: tuple[PriorityGuardrail, ...] = Field(max_length=0)
    review_status: Literal["needs_review"] = "needs_review"
    formal_qualification: Literal["not_proven"] = "not_proven"
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    limitations: tuple[str, ...] = PARTIAL_PRIORITY_LIMITATIONS

    @field_validator("individual_identity_verified", mode="before")
    @classmethod
    def no_identity(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("partial priority cannot verify individual identity")
        return value

    @model_validator(mode="after")
    def partial_profile(self) -> Self:
        components = tuple(
            SourcePartialPriorityComponent.model_validate(row.model_dump(warnings=False))
            for row in self.components
        )
        selected = PartialPriorityEvidenceRef.model_validate(
            self.selected_evidence[0].model_dump(warnings=False)
        )
        if (
            tuple(row.source for row in components) != PRIORITY_SOURCES
            or any(
                row.evidence != (selected if row.source == "policy" else None) for row in components
            )
            or self.limitations != PARTIAL_PRIORITY_LIMITATIONS
        ):
            raise ValueError("partial priority inventory, references or limitations differ")
        observed = components[0].observation
        assert observed is not None
        expected_guards = (
            (PriorityGuardrail(kind="critical_policy", floor=0.90),)
            if observed.critical_policy_present
            else ()
        )
        if self.applicable_guardrails != expected_guards:
            raise ValueError("partial priority must retain applicable adverse policy guards")
        old = SourceEvidenceMember.model_validate(self.before.model_dump(warnings=False))
        new = SourceEvidenceMember.model_validate(self.after.model_dump(warnings=False))
        if (
            old.device_id != new.device_id
            or old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or old.created_at > new.created_at
        ):
            raise ValueError("partial priority target pair differs")
        return self


def compose_partial_source_priority(
    draft: PatchDraft,
    report: SourceEvidenceReportV5,
    deterministic: SourcePartialDiagnostic,
) -> SourcePriorityCompositionV3:
    draft = PatchDraft.model_validate(draft.model_dump(warnings=False))
    report = SourceEvidenceReportV5.model_validate(report.model_dump(warnings=False))
    deterministic = SourcePartialDiagnostic.model_validate(deterministic.model_dump(warnings=False))
    validate_source_evidence_report(report, draft, deterministic)
    selected = PartialPriorityEvidenceRef(
        version=deterministic.version,
        record_id=deterministic.recheck_id,
        review_sha256=deterministic.review_sha256,
    )
    # Reuse the established finding leaf operation, without fabricating a legacy complete DTO.
    observation = _findings(report.deterministic.report.after.policy_findings, "policy_engine")
    components = tuple(
        SourcePartialPriorityComponent(
            source=source,
            status="completed" if source == "policy" else "unavailable",
            reason="finding_priority" if source == "policy" else "not_selected",
            evidence=selected if source == "policy" else None,
            observation=observation if source == "policy" else None,
            raw_score=observation.priority_score if source == "policy" else None,
            configured_weight=_WEIGHTS[source],
            effective_weight=0.0,
            contribution=None,
        )
        for source in PRIORITY_SOURCES
    )
    guards = (
        (PriorityGuardrail(kind="critical_policy", floor=0.90),)
        if observation.critical_policy_present
        else ()
    )
    return SourcePriorityCompositionV3(
        report_id=report.report_id,
        report_sha256=report.review_sha256,
        report_version=report.version,
        patch_id=report.patch_id,
        draft_sha256=report.draft_sha256,
        before=report.before,
        after=report.after,
        before_analysis_id=report.before_analysis_id,
        before_analysis_sha256=report.before_analysis_sha256,
        selected_evidence=(selected,),
        candidate_parser_confidence=report.deterministic.report.after.parse.summary.confidence,
        components=components,
        score=None,
        band=None,
        applicable_guardrails=guards,
        applied_guardrails=(),
    )


def validate_partial_source_priority(
    composition: SourcePriorityCompositionV3,
    draft: PatchDraft,
    report: SourceEvidenceReportV5,
    deterministic: SourcePartialDiagnostic,
) -> None:
    actual = SourcePriorityCompositionV3.model_validate(composition.model_dump(warnings=False))
    expected = compose_partial_source_priority(draft, report, deterministic)
    if actual != expected:
        raise ValueError("partial priority differs from its exact saved report and child")
