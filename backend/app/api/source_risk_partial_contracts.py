"""Saved partial-diagnostic assessments with unavailable aggregate and exact report bindings."""

from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, TypeAdapter, field_validator, model_validator

from app.api import source_risk_scope_contracts as legacy
from app.api.patch_contracts import PatchDraft
from app.api.source_evidence_partial_contracts import (
    SourceEvidenceReportRecord,
    SourceEvidenceReportV5,
)
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck, ml_json
from app.api.source_partial_contracts import (
    SourceDeterministicRecord,
    SourcePartialDiagnostic,
    _DiagnosticFrozen,
)
from app.api.source_patch_scope_contracts import SourcePatchReview
from app.core.permissions import Role
from app.detection.fusion.source_partial_priority import (
    SourcePriorityCompositionV3,
    compose_partial_source_priority,
)
from ml.evaluation.contracts import Digest

MAX_SOURCE_RISK_PROOF_BYTES = legacy.MAX_SOURCE_RISK_PROOF_BYTES
MAX_SOURCE_RISK_BYTES = legacy.MAX_SOURCE_RISK_BYTES
SourceRiskProjectionTooLarge = legacy.SourceRiskProjectionTooLarge


class _ServiceRecord(_DiagnosticFrozen):
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator("individual_identity_verified", mode="before")
    @classmethod
    def exact_unverified_identity(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("service-role priority cannot verify individual identity")
        return value


class CreateSourceRiskAssessmentV3(_DiagnosticFrozen):
    version: Literal["source-risk-request-0.3.0"] = "source-risk-request-0.3.0"
    assessment_id: UUID
    report_sha256: Digest
    profile_version: Literal["source-priority-profile-0.1.0"]


class SourceRiskAssessmentV3(_ServiceRecord):
    version: Literal["source-risk-assessment-0.3.0"] = "source-risk-assessment-0.3.0"
    request: CreateSourceRiskAssessmentV3
    assessment_id: UUID
    patch_id: UUID
    report_id: UUID
    report_sha256: Digest
    report_version: Literal["source-evidence-report-0.5.0"]
    draft_sha256: Digest
    created_at: datetime
    service_role: Literal["engineer", "admin"]
    composition: SourcePriorityCompositionV3
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_RISK_PROOF_BYTES, repr=False)
    review_sha256: Digest

    @model_validator(mode="after")
    def bindings(self) -> Self:
        composition = SourcePriorityCompositionV3.model_validate(
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
            raise ValueError("partial priority assessment identity, parent or timestamp differs")
        proof = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            len(proof.encode()) > MAX_SOURCE_RISK_PROOF_BYTES
            or proof != self.review_json
            or sha256(proof.encode()).hexdigest() != self.review_sha256
            or len(self.model_dump_json(warnings=False).encode()) > MAX_SOURCE_RISK_BYTES
        ):
            raise ValueError("partial priority assessment proof or byte budget differs")
        return self

    @classmethod
    def from_evidence(
        cls,
        draft: PatchDraft,
        report: SourceEvidenceReportV5,
        request: CreateSourceRiskAssessmentV3,
        deterministic: SourcePartialDiagnostic,
        *,
        service_role: Role,
        created_at: datetime,
    ) -> Self:
        request = CreateSourceRiskAssessmentV3.model_validate(request.model_dump(warnings=False))
        report = SourceEvidenceReportV5.model_validate(report.model_dump(warnings=False))
        if (
            request.report_sha256 != report.review_sha256
            or service_role not in {"engineer", "admin"}
            or created_at.utcoffset() is None
            or created_at < report.created_at
        ):
            raise ValueError("partial priority assessment role, selected report or time differs")
        composition = compose_partial_source_priority(draft, report, deterministic)
        values = dict(
            version="source-risk-assessment-0.3.0",
            request=request.model_dump(mode="json"),
            assessment_id=str(request.assessment_id),
            patch_id=str(report.patch_id),
            report_id=str(report.report_id),
            report_sha256=report.review_sha256,
            report_version=report.version,
            draft_sha256=report.draft_sha256,
            created_at=TypeAdapter(datetime).dump_python(created_at, mode="json"),
            service_role=service_role,
            composition=composition.model_dump(mode="json"),
            individual_identity_verified=False,
            approved=False,
            applied=False,
        )
        proof = ml_json(values)
        payload = values | {
            "review_json": proof,
            "review_sha256": sha256(proof.encode()).hexdigest(),
        }
        if (
            len(proof.encode()) > MAX_SOURCE_RISK_PROOF_BYTES
            or len(ml_json(payload).encode()) > MAX_SOURCE_RISK_BYTES
        ):
            raise SourceRiskProjectionTooLarge("Partial priority assessment exceeds its budget.")
        return cls.model_validate(payload)


class SourceRiskSummaryV3(_ServiceRecord):
    version: Literal["source-risk-summary-0.3.0"] = "source-risk-summary-0.3.0"
    assessment_id: UUID
    patch_id: UUID
    report_id: UUID
    report_sha256: Digest
    report_version: Literal["source-evidence-report-0.5.0"]
    draft_sha256: Digest
    review_sha256: Digest
    created_at: datetime
    service_role: Literal["engineer", "admin"]
    profile_version: Literal["source-priority-profile-0.1.0"]
    composition_status: Literal["unavailable"]
    score: None
    band: None
    coverage: Literal["partial"]
    availability_mask: tuple[Literal["policy"]] = ("policy",)
    applicable_guardrails: tuple[Literal["critical_policy"], ...] = Field(max_length=1)

    @model_validator(mode="after")
    def aware(self) -> Self:
        if self.created_at.utcoffset() is None:
            raise ValueError("partial priority summary requires aware time")
        return self

    @classmethod
    def from_assessment(cls, value: SourceRiskAssessmentV3) -> Self:
        value = SourceRiskAssessmentV3.model_validate(value.model_dump(warnings=False))
        return cls(
            assessment_id=value.assessment_id,
            patch_id=value.patch_id,
            report_id=value.report_id,
            report_sha256=value.report_sha256,
            report_version=value.report_version,
            draft_sha256=value.draft_sha256,
            review_sha256=value.review_sha256,
            created_at=value.created_at,
            service_role=value.service_role,
            profile_version=value.composition.profile_version,
            composition_status="unavailable",
            score=None,
            band=None,
            coverage="partial",
            availability_mask=("policy",),
            applicable_guardrails=tuple(
                row.kind for row in value.composition.applicable_guardrails
            ),
        )


type SourceRiskRequest = legacy.SourceRiskRequest | CreateSourceRiskAssessmentV3
type SourceRiskRecord = legacy.SourceRiskRecord | SourceRiskAssessmentV3
type SourceRiskSummaryRecord = legacy.SourceRiskSummaryRecord | SourceRiskSummaryV3
_Request = Annotated[SourceRiskRequest, Field(discriminator="version")]
_Assessment = Annotated[SourceRiskRecord, Field(discriminator="version")]
_REQUEST: TypeAdapter[SourceRiskRequest] = TypeAdapter(_Request)
_ASSESSMENT: TypeAdapter[SourceRiskRecord] = TypeAdapter(_Assessment)


def parse_source_risk_request(value: object) -> SourceRiskRequest:
    if isinstance(value, BaseModel):
        value = value.model_dump(warnings=False)
    if isinstance(value, dict) and "version" not in value:
        value = value | {"version": "source-risk-request-0.1.0"}
    return _REQUEST.validate_python(value)


def parse_source_risk_json(value: str) -> SourceRiskRecord:
    return _ASSESSMENT.validate_json(value)


def source_risk_assessment(
    draft: PatchDraft,
    report: SourceEvidenceReportRecord,
    request: SourceRiskRequest,
    deterministic: SourceDeterministicRecord,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
    service_role: Role,
    created_at: datetime,
) -> SourceRiskRecord:
    request = parse_source_risk_request(request)
    if isinstance(request, CreateSourceRiskAssessmentV3):
        if (
            not isinstance(report, SourceEvidenceReportV5)
            or not isinstance(deterministic, SourcePartialDiagnostic)
            or any(row is not None for row in (forest, neural, network))
        ):
            raise ValueError("partial risk and selected report or child protocols differ")
        return SourceRiskAssessmentV3.from_evidence(
            draft,
            report,
            request,
            deterministic,
            service_role=service_role,
            created_at=created_at,
        )
    if isinstance(report, SourceEvidenceReportV5) or isinstance(
        deterministic, SourcePartialDiagnostic
    ):
        raise ValueError("partial risk and selected report or child protocols differ")
    return legacy.source_risk_assessment(
        draft,
        report,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        service_role=service_role,
        created_at=created_at,
    )


def validate_source_risk_record(
    assessment: SourceRiskRecord,
    draft: PatchDraft,
    report: SourceEvidenceReportRecord,
    deterministic: SourceDeterministicRecord,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
) -> None:
    actual = parse_source_risk_json(assessment.model_dump_json(warnings=False))
    expected = source_risk_assessment(
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
        raise ValueError("partial priority differs from exact saved dependencies")


def source_risk_summary(value: SourceRiskRecord) -> SourceRiskSummaryRecord:
    if isinstance(value, SourceRiskAssessmentV3):
        return SourceRiskSummaryV3.from_assessment(value)
    return legacy.source_risk_summary(value)
