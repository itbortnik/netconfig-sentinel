"""Bounded service-role dispositions for an immutable ordinary evidence report."""

from datetime import datetime
from hashlib import sha256
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.api.source_evidence_contracts import SourceEvidenceMember, SourceEvidenceReport
from app.api.source_ml_contracts import ml_json
from app.core.permissions import Role
from ml.evaluation.contracts import Digest, Frozen

MAX_SOURCE_EVIDENCE_DECISION_BYTES = 32 * 1024
type SourceEvidenceVerdict = Literal["rejected", "needs_more_information"]


class SourceEvidenceDecisionProjectionTooLarge(ValueError):
    """The fresh decision proof exceeds its budget before any storage mutation."""


class ReviewSourceEvidenceReport(Frozen):
    version: Literal["source-evidence-decision-request-0.1.0"] = (
        "source-evidence-decision-request-0.1.0"
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


class SourceEvidenceDecision(Frozen):
    version: Literal["source-evidence-decision-0.1.0"] = "source-evidence-decision-0.1.0"
    request: ReviewSourceEvidenceReport = Field(repr=False)
    decision_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    report_id: UUID
    report_sha256: Digest
    report_version: Literal["source-evidence-report-0.1.0"]
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
        report: SourceEvidenceReport,
        request: ReviewSourceEvidenceReport,
        *,
        service_role: Role,
        created_at: datetime,
    ) -> Self:
        report = SourceEvidenceReport.model_validate(report.model_dump(warnings=False))
        request = ReviewSourceEvidenceReport.model_validate(request.model_dump(warnings=False))
        if (
            request.report_sha256 != report.review_sha256
            or service_role not in {"engineer", "admin"}
            or created_at.utcoffset() is None
            or created_at < report.created_at
        ):
            raise ValueError("decision role, time or selected report differs")
        values = {
            "version": "source-evidence-decision-0.1.0",
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

    def validate_report(self, report: SourceEvidenceReport) -> None:
        expected = self.from_report(
            report, self.request, service_role=self.service_role, created_at=self.created_at
        )
        if ml_json(expected.model_dump(mode="json")) != ml_json(self.model_dump(mode="json")):
            raise ValueError("decision projection differs from selected report")


class SourceEvidenceDecisionSummary(Frozen):
    version: Literal["source-evidence-decision-summary-0.1.0"] = (
        "source-evidence-decision-summary-0.1.0"
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
    def from_decision(cls, decision: SourceEvidenceDecision) -> Self:
        # Storage must validate_report against its integrity-checked parent before projection.
        decision = SourceEvidenceDecision.model_validate(decision.model_dump(warnings=False))
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
