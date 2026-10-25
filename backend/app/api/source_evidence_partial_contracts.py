"""Explicit joint diagnostics over exact saved partial policy results."""

from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from app.api import source_evidence_scope_contracts as legacy
from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import SourceDeterministicSelection
from app.api.source_evidence_contracts import (
    MAX_SOURCE_EVIDENCE_BYTES,
    Blockers,
    SelectedEvidenceRef,
    SourceEvidenceMember,
    SourceEvidenceProjectionTooLarge,
    _CompletedEvidence,
    _member,
    source_evidence_blockers,
)
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck, ml_json
from app.api.source_partial_contracts import (
    PartialMode,
    SourceDeterministicRecord,
    SourcePartialDiagnostic,
    SourcePartialReport,
    _DiagnosticFrozen,
)
from app.api.source_patch_scope_contracts import SourcePatchReview
from ml.evaluation.contracts import Digest


class CreateSourceEvidenceReportV5(_DiagnosticFrozen):
    version: Literal["source-evidence-request-0.5.0"] = "source-evidence-request-0.5.0"
    mode: PartialMode
    report_id: UUID
    draft_sha256: Digest
    deterministic: SelectedEvidenceRef
    forest: None
    neural: None
    network: None


class SourcePartialEvidence(_CompletedEvidence):
    model_config = ConfigDict(revalidate_instances="always")
    kind: Literal["deterministic"] = "deterministic"
    version: Literal["source-deterministic-recheck-0.2.0"]
    selection: SourceDeterministicSelection
    before_analysis_status: Literal["completed", "partial"]
    report: SourcePartialReport

    @model_validator(mode="after")
    def scope(self) -> Self:
        report = SourcePartialReport.model_validate(self.report.model_dump(warnings=False))
        selected = SourceDeterministicSelection.model_validate(
            self.selection.model_dump(warnings=False)
        )
        if (
            selected.original.comparison is not None
            or selected.original.statistical_present
            or selected.reference is not None
            or self.before_analysis_status
            != ("completed" if report.before.parse.summary.complete else "partial")
            or report.policy_catalog_version != selected.original.policy_catalog_version
            or ml_json([row.model_dump(mode="json") for row in report.before.policy_findings])
            != ml_json([row.model_dump(mode="json") for row in selected.original.findings])
        ):
            raise ValueError("joint partial projection differs from its recorded original scope")
        return self


def partial_evidence_blockers() -> tuple[str, ...]:
    return (
        *source_evidence_blockers(False, None, None, None),
        "partial_parsing",
        "partial_comparison_unavailable",
    )


class SourceEvidenceReportV5(_DiagnosticFrozen):
    version: Literal["source-evidence-report-0.5.0"] = "source-evidence-report-0.5.0"
    mode: PartialMode = "policy_only_partial_diagnostic"
    coverage: Literal["partial"] = "partial"
    request: CreateSourceEvidenceReportV5
    report_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before: SourceEvidenceMember
    after: SourceEvidenceMember
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    original_statistical_present: Literal[False] = False
    created_at: datetime
    deterministic: SourcePartialEvidence
    forest: None
    neural: None
    network: None
    validation_blockers: Blockers
    status: Literal["needs_review"] = "needs_review"
    formal_qualification: Literal["not_proven"] = "not_proven"
    risk_fused: Literal[False] = False
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_EVIDENCE_BYTES, repr=False)
    review_sha256: Digest

    @field_validator("original_statistical_present", mode="before")
    @classmethod
    def no_original_statistical(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("partial diagnostic cannot claim an original statistical result")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        request = CreateSourceEvidenceReportV5.model_validate(
            self.request.model_dump(warnings=False)
        )
        child = SourcePartialEvidence.model_validate(self.deterministic.model_dump(warnings=False))
        old = SourceEvidenceMember.model_validate(self.before.model_dump(warnings=False))
        new = SourceEvidenceMember.model_validate(self.after.model_dump(warnings=False))
        if (
            self.created_at.utcoffset() is None
            or request.report_id != self.report_id
            or request.draft_sha256 != self.draft_sha256
            or old.device_id != new.device_id
            or old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or not old.created_at
            <= new.created_at
            <= child.created_at
            <= child.completed_at
            <= self.created_at
            or self.validation_blockers != partial_evidence_blockers()
            or (request.deterministic.record_id, request.deterministic.review_sha256)
            != (child.record_id, child.review_sha256)
            or (
                self.patch_id,
                self.draft_sha256,
                self.before_analysis_id,
                self.before_analysis_sha256,
            )
            != (
                child.selection.patch_id,
                child.selection.draft_sha256,
                child.selection.before_analysis_id,
                child.selection.before_analysis_sha256,
            )
            or child.selection.before.model_dump() != old.model_dump(exclude={"canonical_sha256"})
        ):
            raise ValueError("joint partial diagnostic parent, child, scope or chronology differs")
        for side, member in ((child.report.before, old), (child.report.after, new)):
            if (side.configuration_id, side.source_sha256) != (
                member.configuration_id,
                member.source_sha256,
            ) or any(row.device_id != member.device_id for row in side.policy_findings):
                raise ValueError("joint partial diagnostic target source or device differs")
        proof = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            len(proof.encode()) > MAX_SOURCE_EVIDENCE_BYTES
            or proof != self.review_json
            or sha256(proof.encode()).hexdigest() != self.review_sha256
        ):
            raise ValueError("joint partial diagnostic proof differs")
        return self

    @classmethod
    def from_evidence(
        cls,
        draft: PatchDraft,
        request: CreateSourceEvidenceReportV5,
        deterministic: SourcePartialDiagnostic,
        *,
        created_at: datetime,
    ) -> Self:
        draft = PatchDraft.model_validate(draft.model_dump(warnings=False))
        request = CreateSourceEvidenceReportV5.model_validate(request.model_dump(warnings=False))
        deterministic = SourcePartialDiagnostic.model_validate(
            deterministic.model_dump(warnings=False)
        )
        if (
            draft.diff.coverage != "partial"
            or request.draft_sha256 != draft.draft_sha256
            or deterministic.patch_id != draft.patch_id
            or deterministic.draft_sha256 != draft.draft_sha256
            or deterministic.execution_status != "completed"
            or deterministic.outcome is None
            or deterministic.outcome.report is None
            or created_at.utcoffset() is None
            or created_at < draft.created_at
        ):
            raise ValueError("joint partial diagnostic requires the exact completed selected child")
        intent, outcome = deterministic.intent, deterministic.outcome
        for member, anchor, parsed in (
            (intent.before, draft.diff.before, intent.before_parse),
            (intent.after, draft.diff.after, intent.after_parse),
        ):
            if (
                member.configuration_id,
                member.device_id,
                member.source_sha256,
                member.created_at,
            ) != (
                anchor.configuration_id,
                anchor.device_id,
                anchor.source_sha256,
                anchor.created_at,
            ) or (
                parsed.summary.confidence,
                parsed.summary.warning_count,
                parsed.summary.unparsed_count,
            ) != (anchor.parser_confidence, anchor.warning_count, anchor.unparsed_count):
                raise ValueError(
                    "joint partial diagnostic source or parser summary differs from draft"
                )
        assert outcome.report is not None
        projection = SourcePartialEvidence(
            version=deterministic.version,
            record_id=deterministic.recheck_id,
            review_sha256=deterministic.review_sha256,
            created_at=intent.created_at,
            completed_at=outcome.completed_at,
            selection=intent.selection,
            before_analysis_status=intent.before_analysis_status,
            report=outcome.report,
            validation_blockers=deterministic.validation_blockers,
        )
        values = dict(
            version="source-evidence-report-0.5.0",
            mode="policy_only_partial_diagnostic",
            coverage="partial",
            request=request.model_dump(mode="json"),
            report_id=str(request.report_id),
            patch_id=str(draft.patch_id),
            draft_sha256=draft.draft_sha256,
            before=_member(intent.before).model_dump(mode="json"),
            after=_member(intent.after).model_dump(mode="json"),
            before_analysis_id=str(intent.request.before_analysis_id),
            before_analysis_sha256=intent.request.before_analysis_sha256,
            original_statistical_present=False,
            created_at=TypeAdapter(datetime).dump_python(created_at, mode="json"),
            deterministic=projection.model_dump(mode="json"),
            forest=None,
            neural=None,
            network=None,
            validation_blockers=partial_evidence_blockers(),
            status="needs_review",
            formal_qualification="not_proven",
            risk_fused=False,
            calibrated=False,
            quality_proven=False,
            approved=False,
            applied=False,
        )
        proof = ml_json(values)
        if len(proof.encode()) > MAX_SOURCE_EVIDENCE_BYTES:
            raise SourceEvidenceProjectionTooLarge("Joint partial diagnostic exceeds its budget.")
        return cls.model_validate(
            values | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}
        )


class SourceEvidenceSummaryV5(_DiagnosticFrozen):
    version: Literal["source-evidence-summary-0.5.0"] = "source-evidence-summary-0.5.0"
    mode: PartialMode = "policy_only_partial_diagnostic"
    coverage: Literal["partial"] = "partial"
    report_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    review_sha256: Digest
    created_at: datetime
    selected_kinds: tuple[Literal["deterministic"]] = ("deterministic",)
    status: Literal["needs_review"] = "needs_review"

    @model_validator(mode="after")
    def aware(self) -> Self:
        if self.created_at.utcoffset() is None:
            raise ValueError("joint diagnostic summary requires aware time")
        return self

    @classmethod
    def from_report(cls, report: SourceEvidenceReportV5) -> Self:
        report = SourceEvidenceReportV5.model_validate(report.model_dump(warnings=False))
        return cls(
            report_id=report.report_id,
            patch_id=report.patch_id,
            draft_sha256=report.draft_sha256,
            before_analysis_id=report.before_analysis_id,
            review_sha256=report.review_sha256,
            created_at=report.created_at,
        )


type SourceEvidenceRequest = legacy.SourceEvidenceRequest | CreateSourceEvidenceReportV5
type SourceEvidenceReportRecord = legacy.SourceEvidenceReportRecord | SourceEvidenceReportV5
type SourceEvidenceSummaryRecord = legacy.SourceEvidenceSummaryRecord | SourceEvidenceSummaryV5
_Request = Annotated[SourceEvidenceRequest, Field(discriminator="version")]
_Report = Annotated[SourceEvidenceReportRecord, Field(discriminator="version")]
_REQUEST: TypeAdapter[SourceEvidenceRequest] = TypeAdapter(_Request)
_REPORT: TypeAdapter[SourceEvidenceReportRecord] = TypeAdapter(_Report)


def parse_source_evidence_request(value: object) -> SourceEvidenceRequest:
    if isinstance(value, BaseModel):
        value = value.model_dump(warnings=False)
    if isinstance(value, dict) and "version" not in value:
        value = value | {"version": "source-evidence-request-0.1.0"}
    return _REQUEST.validate_python(value)


def parse_source_evidence_report_json(value: str) -> SourceEvidenceReportRecord:
    return _REPORT.validate_json(value)


def source_evidence_report(
    draft: PatchDraft,
    request: SourceEvidenceRequest,
    deterministic: SourceDeterministicRecord,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
    created_at: datetime,
) -> SourceEvidenceReportRecord:
    request = parse_source_evidence_request(request)
    if isinstance(request, CreateSourceEvidenceReportV5):
        if not isinstance(deterministic, SourcePartialDiagnostic) or any(
            row is not None for row in (forest, neural, network)
        ):
            raise ValueError(
                "partial diagnostic report cannot select complete or optional children"
            )
        return SourceEvidenceReportV5.from_evidence(
            draft, request, deterministic, created_at=created_at
        )
    if isinstance(deterministic, SourcePartialDiagnostic):
        raise ValueError("partial diagnostic child requires its explicit report protocol")
    return legacy.source_evidence_report(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=created_at,
    )


def validate_source_evidence_report(
    report: SourceEvidenceReportRecord,
    draft: PatchDraft,
    deterministic: SourceDeterministicRecord,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
) -> None:
    actual = parse_source_evidence_report_json(report.model_dump_json(warnings=False))
    expected = source_evidence_report(
        draft,
        actual.request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=actual.created_at,
    )
    if actual != expected:
        raise ValueError("joint diagnostic differs from the full saved child projection")


def source_evidence_summary(report: SourceEvidenceReportRecord) -> SourceEvidenceSummaryRecord:
    if isinstance(report, SourceEvidenceReportV5):
        return SourceEvidenceSummaryV5.from_report(report)
    return legacy.source_evidence_summary(report)
