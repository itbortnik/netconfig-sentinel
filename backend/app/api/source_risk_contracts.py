"""Immutable experimental priority assessments over exact saved report dependencies."""

from datetime import datetime
from hashlib import sha256
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import SourceDeterministicRecheck
from app.api.source_evidence_direction_contracts import (
    SourceEvidenceReportRecord,
    parse_source_evidence_report_json,
)
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck, ml_json
from app.api.source_patch_direction_contracts import SourcePatchReview
from app.core.permissions import Role
from app.detection.fusion.source_priority import (
    PRIORITY_SOURCES,
    PriorityBand,
    PrioritySource,
    SourcePriorityComposition,
    compose_source_priority,
    validate_source_priority,
)
from ml.evaluation.contracts import Digest, Frozen, UnitScore

MAX_SOURCE_RISK_PROOF_BYTES = 1024 * 1024
MAX_SOURCE_RISK_BYTES = 2 * 1024 * 1024
type ReportVersion = Literal[
    "source-evidence-report-0.1.0", "source-evidence-report-0.2.0", "source-evidence-report-0.3.0"
]
type GuardrailCode = Literal["critical_policy", "observed_scoped_loss"]


class SourceRiskProjectionTooLarge(ValueError):
    """The new bounded assessment cannot be stored without truncating its proof."""


class CreateSourceRiskAssessment(Frozen):
    version: Literal["source-risk-request-0.1.0"] = "source-risk-request-0.1.0"
    assessment_id: UUID
    report_sha256: Digest
    profile_version: Literal["source-priority-profile-0.1.0"]


class SourceRiskAssessment(Frozen):
    version: Literal["source-risk-assessment-0.1.0"] = "source-risk-assessment-0.1.0"
    request: CreateSourceRiskAssessment
    assessment_id: UUID
    patch_id: UUID
    report_id: UUID
    report_sha256: Digest
    report_version: ReportVersion
    draft_sha256: Digest
    created_at: datetime
    service_role: Literal["engineer", "admin"]
    composition: SourcePriorityComposition
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_RISK_PROOF_BYTES, repr=False)
    review_sha256: Digest

    @field_validator("individual_identity_verified", "approved", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("priority assessment cannot verify identity, approve or apply")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        composition = SourcePriorityComposition.model_validate(
            self.composition.model_dump(warnings=False)
        )
        if (
            self.assessment_id != self.request.assessment_id
            or self.request.report_sha256 != self.report_sha256
            or self.request.profile_version != composition.profile_version
            or self.created_at.utcoffset() is None
            or (
                self.patch_id,
                self.report_id,
                self.report_sha256,
                self.report_version,
                self.draft_sha256,
            )
            != (
                composition.patch_id,
                composition.report_id,
                composition.report_sha256,
                composition.report_version,
                composition.draft_sha256,
            )
        ):
            raise ValueError("priority assessment identity, parent or timestamp differs")
        proof = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            len(proof.encode()) > MAX_SOURCE_RISK_PROOF_BYTES
            or proof != self.review_json
            or sha256(proof.encode()).hexdigest() != self.review_sha256
            or len(self.model_dump_json(warnings=False).encode()) > MAX_SOURCE_RISK_BYTES
        ):
            raise ValueError("priority assessment proof or byte budget differs")
        return self

    @classmethod
    def from_evidence(
        cls,
        draft: PatchDraft,
        report: SourceEvidenceReportRecord,
        request: CreateSourceRiskAssessment,
        deterministic: SourceDeterministicRecheck,
        *,
        forest: SourceForestRecheck | None = None,
        neural: SourceMlRecheck | None = None,
        network: SourcePatchReview | None = None,
        service_role: Role,
        created_at: datetime,
    ) -> Self:
        report = parse_source_evidence_report_json(report.model_dump_json(warnings=False))
        request = CreateSourceRiskAssessment.model_validate(request.model_dump(warnings=False))
        if (
            request.report_sha256 != report.review_sha256
            or service_role not in {"engineer", "admin"}
            or created_at.utcoffset() is None
            or created_at < report.created_at
        ):
            raise ValueError("priority assessment role, time or selected report differs")
        composition = compose_source_priority(
            draft, report, deterministic, forest=forest, neural=neural, network=network
        )
        values = {
            "version": "source-risk-assessment-0.1.0",
            "request": request.model_dump(mode="json"),
            "assessment_id": str(request.assessment_id),
            "patch_id": str(report.patch_id),
            "report_id": str(report.report_id),
            "report_sha256": report.review_sha256,
            "report_version": report.version,
            "draft_sha256": report.draft_sha256,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "service_role": service_role,
            "composition": composition.model_dump(mode="json"),
            "individual_identity_verified": False,
            "approved": False,
            "applied": False,
        }
        proof = ml_json(values)
        if len(proof.encode()) > MAX_SOURCE_RISK_PROOF_BYTES:
            raise SourceRiskProjectionTooLarge("Priority assessment exceeds its proof budget.")
        value = values | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}
        if len(ml_json(value).encode()) > MAX_SOURCE_RISK_BYTES:
            raise SourceRiskProjectionTooLarge("Priority assessment exceeds its payload budget.")
        return cls.model_validate(value)

    def validate_evidence(
        self,
        draft: PatchDraft,
        report: SourceEvidenceReportRecord,
        deterministic: SourceDeterministicRecheck,
        *,
        forest: SourceForestRecheck | None = None,
        neural: SourceMlRecheck | None = None,
        network: SourcePatchReview | None = None,
    ) -> None:
        actual = type(self).model_validate(self.model_dump(warnings=False))
        validate_source_priority(
            actual.composition,
            draft,
            report,
            deterministic,
            forest=forest,
            neural=neural,
            network=network,
        )
        expected = type(self).from_evidence(
            draft,
            report,
            actual.request,
            deterministic,
            forest=forest,
            neural=neural,
            network=network,
            service_role=actual.service_role,
            created_at=actual.created_at,
        )
        if actual != expected:
            raise ValueError("priority assessment differs from complete selected evidence")


class SourceRiskSummary(Frozen):
    version: Literal["source-risk-summary-0.1.0"] = "source-risk-summary-0.1.0"
    assessment_id: UUID
    patch_id: UUID
    report_id: UUID
    report_sha256: Digest
    report_version: ReportVersion
    draft_sha256: Digest
    review_sha256: Digest
    created_at: datetime
    service_role: Literal["engineer", "admin"]
    profile_version: Literal["source-priority-profile-0.1.0"]
    composition_status: Literal["completed", "unavailable"]
    score: UnitScore | None
    band: PriorityBand | None
    coverage: Literal["supported_complete", "partial"]
    availability_mask: tuple[PrioritySource, ...] = Field(min_length=1, max_length=5)
    applicable_guardrails: tuple[GuardrailCode, ...] = Field(max_length=2)
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator("individual_identity_verified", "approved", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("priority summary cannot verify identity, approve or apply")
        return value

    @model_validator(mode="after")
    def consistent_summary(self) -> Self:
        complete = self.coverage == "supported_complete"
        if (
            self.created_at.utcoffset() is None
            or (self.composition_status == "completed") != complete
            or (self.score is not None) != complete
            or (self.band is not None) != complete
            or self.availability_mask
            != tuple(source for source in PRIORITY_SOURCES if source in self.availability_mask)
            or self.availability_mask[0] != "policy"
            or self.applicable_guardrails
            != tuple(
                code
                for code in ("critical_policy", "observed_scoped_loss")
                if code in self.applicable_guardrails
            )
        ):
            raise ValueError("priority summary state, mask or chronology differs")
        if self.score is not None:
            expected = (
                "critical"
                if self.score >= 0.80
                else "high"
                if self.score >= 0.50
                else "medium"
                if self.score >= 0.25
                else "low"
            )
            if self.band != expected:
                raise ValueError("priority summary band differs from its engineering score")
        return self

    @classmethod
    def from_assessment(cls, assessment: SourceRiskAssessment) -> Self:
        # The repository must validate the full dependency chain before calling this projection.
        assessment = SourceRiskAssessment.model_validate(assessment.model_dump(warnings=False))
        comp = assessment.composition
        return cls(
            assessment_id=assessment.assessment_id,
            patch_id=assessment.patch_id,
            report_id=assessment.report_id,
            report_sha256=assessment.report_sha256,
            report_version=assessment.report_version,
            draft_sha256=assessment.draft_sha256,
            review_sha256=assessment.review_sha256,
            created_at=assessment.created_at,
            service_role=assessment.service_role,
            profile_version=comp.profile_version,
            composition_status=comp.status,
            score=comp.score,
            band=comp.band,
            coverage=comp.coverage,
            availability_mask=comp.availability_mask,
            applicable_guardrails=tuple(row.kind for row in comp.applicable_guardrails),
        )
