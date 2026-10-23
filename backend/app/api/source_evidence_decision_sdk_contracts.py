"""Service-role dispositions pinned to SDK-aware reports, without identity or approval promotion."""

from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, TypeAdapter, field_validator, model_validator

from app.api.source_evidence_contracts import SourceEvidenceMember, SourceEvidenceReport
from app.api.source_evidence_decision_contracts import (
    MAX_SOURCE_EVIDENCE_DECISION_BYTES,
    ReviewSourceEvidenceReport,
    SourceEvidenceDecision,
    SourceEvidenceDecisionProjectionTooLarge,
    SourceEvidenceDecisionSummary,
    SourceEvidenceVerdict,
)
from app.api.source_evidence_sdk_contracts import SourceEvidenceReportRecord, SourceEvidenceReportV2
from app.api.source_ml_contracts import ml_json
from app.core.permissions import Role
from ml.evaluation.contracts import Digest, Frozen


class ReviewSourceEvidenceReportV2(Frozen):
    version: Literal["source-evidence-decision-request-0.2.0"] = (
        "source-evidence-decision-request-0.2.0"
    )
    decision_id: UUID
    report_sha256: Digest
    verdict: SourceEvidenceVerdict
    comment: str = Field(min_length=1, max_length=1200, repr=False)

    @field_validator("comment")
    @classmethod
    def bounded_comment(cls, value: str) -> str:
        if not value.strip() or any(
            not char.isprintable() and char not in "\n\t" for char in value
        ):
            raise ValueError("invalid review comment")
        return value


class SourceEvidenceDecisionV2(Frozen):
    version: Literal["source-evidence-decision-0.2.0"] = "source-evidence-decision-0.2.0"
    request: ReviewSourceEvidenceReportV2 = Field(repr=False)
    decision_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    report_id: UUID
    report_sha256: Digest
    report_version: Literal["source-evidence-report-0.2.0"]
    before: SourceEvidenceMember
    after: SourceEvidenceMember
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    created_at: datetime
    service_role: Literal["engineer", "admin"]
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    decision_json: str = Field(
        min_length=1, max_length=MAX_SOURCE_EVIDENCE_DECISION_BYTES, repr=False
    )
    decision_sha256: Digest

    @field_validator("individual_identity_verified", "approved", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("service-role disposition cannot verify identity, approve or apply")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if (
            self.decision_id != self.request.decision_id
            or self.report_sha256 != self.request.report_sha256
            or self.created_at.utcoffset() is None
            or self.before.device_id != self.after.device_id
            or self.before.configuration_id == self.after.configuration_id
            or self.before.source_sha256 == self.after.source_sha256
        ):
            raise ValueError("decision identity, source or timestamp differs")
        proof = ml_json(self.model_dump(mode="json", exclude={"decision_json", "decision_sha256"}))
        if (
            len(proof.encode()) > MAX_SOURCE_EVIDENCE_DECISION_BYTES
            or proof != self.decision_json
            or sha256(proof.encode()).hexdigest() != self.decision_sha256
        ):
            raise ValueError("decision proof differs")
        return self

    @classmethod
    def from_report(
        cls,
        report: SourceEvidenceReportV2,
        request: ReviewSourceEvidenceReportV2,
        *,
        service_role: Role,
        created_at: datetime,
    ) -> Self:
        report = SourceEvidenceReportV2.model_validate(report.model_dump(warnings=False))
        request = ReviewSourceEvidenceReportV2.model_validate(request.model_dump(warnings=False))
        if (
            request.report_sha256 != report.review_sha256
            or service_role not in {"engineer", "admin"}
            or created_at.utcoffset() is None
            or created_at < report.created_at
        ):
            raise ValueError("decision role, time or selected report differs")
        values = {
            "version": "source-evidence-decision-0.2.0",
            "request": request.model_dump(mode="json"),
            "decision_id": str(request.decision_id),
            "patch_id": str(report.patch_id),
            "draft_sha256": report.draft_sha256,
            "report_id": str(report.report_id),
            "report_sha256": report.review_sha256,
            "report_version": report.version,
            "before": report.before.model_dump(mode="json"),
            "after": report.after.model_dump(mode="json"),
            "before_analysis_id": str(report.before_analysis_id),
            "before_analysis_sha256": report.before_analysis_sha256,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "service_role": service_role,
            "individual_identity_verified": False,
            "approved": False,
            "applied": False,
        }
        proof = ml_json(values)
        if len(proof.encode()) > MAX_SOURCE_EVIDENCE_DECISION_BYTES:
            raise SourceEvidenceDecisionProjectionTooLarge("Decision proof exceeds its budget.")
        return cls.model_validate(
            values | {"decision_json": proof, "decision_sha256": sha256(proof.encode()).hexdigest()}
        )

    def validate_report(self, report: SourceEvidenceReportV2) -> None:
        expected = self.from_report(
            report, self.request, service_role=self.service_role, created_at=self.created_at
        )
        if ml_json(expected.model_dump(mode="json")) != ml_json(self.model_dump(mode="json")):
            raise ValueError("decision projection differs from selected report")


class SourceEvidenceDecisionSummaryV2(Frozen):
    version: Literal["source-evidence-decision-summary-0.2.0"] = (
        "source-evidence-decision-summary-0.2.0"
    )
    decision_id: UUID
    patch_id: UUID
    report_id: UUID
    report_sha256: Digest
    decision_sha256: Digest
    created_at: datetime
    verdict: SourceEvidenceVerdict
    service_role: Literal["engineer", "admin"]
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator("individual_identity_verified", "approved", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("decision summary cannot promote identity, approval or application")
        return value

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("decision summary requires an aware timestamp")
        return value

    @classmethod
    def from_decision(cls, decision: SourceEvidenceDecisionV2) -> Self:
        # Storage must validate_report against its integrity-checked parent before projection.
        decision = SourceEvidenceDecisionV2.model_validate(decision.model_dump(warnings=False))
        return cls(
            decision_id=decision.decision_id,
            patch_id=decision.patch_id,
            report_id=decision.report_id,
            report_sha256=decision.report_sha256,
            decision_sha256=decision.decision_sha256,
            created_at=decision.created_at,
            verdict=decision.request.verdict,
            service_role=decision.service_role,
        )


SourceEvidenceDecisionRequest = ReviewSourceEvidenceReport | ReviewSourceEvidenceReportV2
SourceEvidenceDecisionRecord = SourceEvidenceDecision | SourceEvidenceDecisionV2
SourceEvidenceDecisionSummaryRecord = (
    SourceEvidenceDecisionSummary | SourceEvidenceDecisionSummaryV2
)
_REQUEST: TypeAdapter[SourceEvidenceDecisionRequest] = TypeAdapter(
    Annotated[SourceEvidenceDecisionRequest, Field(discriminator="version")]
)
_DECISION: TypeAdapter[SourceEvidenceDecisionRecord] = TypeAdapter(
    Annotated[SourceEvidenceDecisionRecord, Field(discriminator="version")]
)


def parse_source_evidence_decision_request(value: object) -> SourceEvidenceDecisionRequest:
    if isinstance(value, BaseModel):
        value = value.model_dump(warnings=False)
    if isinstance(value, dict) and "version" not in value:
        value = value | {"version": "source-evidence-decision-request-0.1.0"}
    return _REQUEST.validate_python(value)


def parse_source_evidence_decision_json(value: str) -> SourceEvidenceDecisionRecord:
    return _DECISION.validate_json(value)


def source_evidence_decision(
    report: SourceEvidenceReportRecord,
    request: SourceEvidenceDecisionRequest,
    *,
    service_role: Role,
    created_at: datetime,
) -> SourceEvidenceDecisionRecord:
    request = parse_source_evidence_decision_request(request)
    if isinstance(request, ReviewSourceEvidenceReportV2):
        if not isinstance(report, SourceEvidenceReportV2):
            raise ValueError("decision and selected report protocols differ")
        return SourceEvidenceDecisionV2.from_report(
            report,
            request,
            service_role=service_role,
            created_at=created_at,
        )
    if not isinstance(report, SourceEvidenceReport):
        raise ValueError("decision and selected report protocols differ")
    return SourceEvidenceDecision.from_report(
        report,
        request,
        service_role=service_role,
        created_at=created_at,
    )


def validate_source_evidence_decision(
    decision: SourceEvidenceDecisionRecord,
    report: SourceEvidenceReportRecord,
) -> None:
    actual = parse_source_evidence_decision_json(decision.model_dump_json(warnings=False))
    expected = source_evidence_decision(
        report,
        actual.request,
        service_role=actual.service_role,
        created_at=actual.created_at,
    )
    if actual != expected:
        raise ValueError("decision projection differs from selected report")


def source_evidence_decision_summary(
    decision: SourceEvidenceDecisionRecord,
) -> SourceEvidenceDecisionSummaryRecord:
    if isinstance(decision, SourceEvidenceDecisionV2):
        return SourceEvidenceDecisionSummaryV2.from_decision(decision)
    return SourceEvidenceDecisionSummary.from_decision(decision)
