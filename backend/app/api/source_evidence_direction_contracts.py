"""Immutable directional reports and strict dispatch to historical report protocols."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, StrictBool, TypeAdapter, field_validator, model_validator

from app.api import source_evidence_sdk_contracts as sdk
from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import SourceDeterministicRecheck
from app.api.source_evidence_contracts import (
    _EVIDENCE_KINDS,
    MAX_SOURCE_EVIDENCE_BYTES,
    Blockers,
    SelectedEvidenceRef,
    SourceDeterministicEvidence,
    SourceEvidenceMember,
    SourceEvidenceProjectionTooLarge,
    SourceForestEvidence,
    SourceNetworkEvidence,
    SourceNeuralEvidence,
    _CompletedEvidence,
    _deterministic_projection,
    _forest_projection,
    _member,
    _neural_projection,
    source_evidence_blockers,
)
from app.api.source_evidence_sdk_contracts import SourceNetworkEvidenceV2, _network_projection_v2
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck, ml_json
from app.api.source_patch_direction_contracts import SourcePatchReview, SourcePatchVerificationV3
from app.verification.batfish import BatfishResult
from app.verification.reachability_impact import BatfishDirectionalExecution, ReachabilityImpact
from app.verification.source_evidence import EvidenceKind, bind_selected_source_evidence
from ml.evaluation.contracts import Digest, Frozen


class CreateSourceEvidenceReportV3(Frozen):
    version: Literal["source-evidence-request-0.3.0"] = "source-evidence-request-0.3.0"
    report_id: UUID
    draft_sha256: Digest
    deterministic: SelectedEvidenceRef
    forest: SelectedEvidenceRef | None
    neural: SelectedEvidenceRef | None
    network: SelectedEvidenceRef | None


class SourceNetworkEvidenceV3(_CompletedEvidence):
    kind: Literal["network"] = "network"
    version: Literal["source-patch-verification-0.3.0"]
    result: BatfishResult
    execution_version: Literal["batfish-execution-0.3.0"]
    sdk_version: str | None
    sdk_observation: Literal["observed", "not_observed", "metadata_unavailable"]
    reachability_impact: ReachabilityImpact
    ml_status: Literal["not_run"] = "not_run"
    network_device_count: int = Field(ge=1, le=32, strict=True)

    @model_validator(mode="after")
    def recorded_execution(self) -> Self:
        BatfishDirectionalExecution(
            version=self.execution_version,
            result=self.result,
            sdk_version=self.sdk_version,
            sdk_observation=self.sdk_observation,
            reachability_impact=self.reachability_impact,
        )
        return self


def _network_projection_v3(
    value: SourcePatchReview,
) -> SourceNetworkEvidence | SourceNetworkEvidenceV2 | SourceNetworkEvidenceV3:
    if not isinstance(value, SourcePatchVerificationV3):
        return _network_projection_v2(value)
    assert value.outcome is not None
    execution = value.outcome.network_execution
    return SourceNetworkEvidenceV3(
        version=value.version,
        record_id=value.verification_id,
        review_sha256=value.review_sha256,
        created_at=value.intent.created_at,
        completed_at=value.outcome.completed_at,
        validation_blockers=value.validation_blockers,
        result=execution.result,
        execution_version=execution.version,
        sdk_version=execution.sdk_version,
        sdk_observation=execution.sdk_observation,
        reachability_impact=execution.reachability_impact,
        network_device_count=1 + len(value.intent.companions),
    )


class SourceEvidenceReportV3(Frozen):
    version: Literal["source-evidence-report-0.3.0"] = "source-evidence-report-0.3.0"
    request: CreateSourceEvidenceReportV3
    report_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before: SourceEvidenceMember
    after: SourceEvidenceMember
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    original_statistical_present: StrictBool
    created_at: datetime
    deterministic: SourceDeterministicEvidence
    forest: SourceForestEvidence | None
    neural: SourceNeuralEvidence | None
    network: (
        Annotated[
            SourceNetworkEvidence | SourceNetworkEvidenceV2 | SourceNetworkEvidenceV3,
            Field(discriminator="version"),
        ]
        | None
    )
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

    @field_validator(
        "risk_fused", "calibrated", "quality_proven", "approved", "applied", mode="before"
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("joint evidence cannot promote safety, quality or approval")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if (
            self.created_at.utcoffset() is None
            or self.request.report_id != self.report_id
            or self.request.draft_sha256 != self.draft_sha256
            or self.before.device_id != self.after.device_id
            or self.before.configuration_id == self.after.configuration_id
            or self.before.source_sha256 == self.after.source_sha256
            or not self.before.created_at <= self.after.created_at <= self.created_at
            or (self.forest is not None and not self.original_statistical_present)
            or self.validation_blockers
            != source_evidence_blockers(
                self.original_statistical_present, self.forest, self.neural, self.network
            )
        ):
            raise ValueError("joint evidence parent, scope or qualification differs")
        for kind in _EVIDENCE_KINDS:
            reference, evidence = getattr(self.request, kind), getattr(self, kind)
            if (reference is None) != (evidence is None):
                raise ValueError("joint evidence selection differs")
            if evidence is not None and (
                reference.record_id != evidence.record_id
                or reference.review_sha256 != evidence.review_sha256
                or evidence.created_at < self.after.created_at
                or evidence.completed_at > self.created_at
            ):
                raise ValueError("joint evidence selected identity or chronology differs")
        reference = self.deterministic.reference
        if reference is not None and (
            reference.device_id != self.before.device_id
            or reference.configuration_id
            in {self.before.configuration_id, self.after.configuration_id}
            or reference.created_at > self.before.created_at
        ):
            raise ValueError("joint evidence original reference differs")
        if self.neural is not None and any(
            side.raw_source_sha256 != member.source_sha256
            for side, member in ((self.neural.before, self.before), (self.neural.after, self.after))
        ):
            raise ValueError("joint neural evidence belongs to another source")
        expected = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            len(self.review_json.encode()) > MAX_SOURCE_EVIDENCE_BYTES
            or self.review_json != expected
            or self.review_sha256 != sha256(expected.encode()).hexdigest()
        ):
            raise ValueError("joint evidence review proof differs")
        return self

    @classmethod
    def from_evidence(
        cls,
        draft: PatchDraft,
        request: CreateSourceEvidenceReportV3,
        deterministic: SourceDeterministicRecheck,
        *,
        forest: SourceForestRecheck | None = None,
        neural: SourceMlRecheck | None = None,
        network: SourcePatchReview | None = None,
        created_at: datetime,
    ) -> Self:
        """Project integrity-checked records without reading a repository or running detectors."""
        selected = bind_selected_source_evidence(
            draft, deterministic, forest=forest, neural=neural, network=network
        )
        request = CreateSourceEvidenceReportV3.model_validate(request.model_dump())
        if request.draft_sha256 != draft.draft_sha256 or any(
            (getattr(request, kind) is not None) != (kind in {row.kind for row in selected})
            for kind in _EVIDENCE_KINDS
        ):
            raise ValueError("joint request draft or selected evidence differs")
        for row in selected:
            reference = getattr(request, row.kind)
            if (reference.record_id, reference.review_sha256) != (row.record_id, row.review_sha256):
                raise ValueError("joint request selected identity differs")
        if created_at.utcoffset() is None or created_at < draft.created_at:
            raise ValueError("joint evidence cannot precede its draft")
        deterministic_projection = _deterministic_projection(deterministic)
        forest_projection = _forest_projection(forest) if forest is not None else None
        neural_projection = _neural_projection(neural) if neural is not None else None
        network_projection = _network_projection_v3(network) if network is not None else None
        statistical = deterministic.intent.selection.original.statistical_present
        value = {
            "version": "source-evidence-report-0.3.0",
            "request": request.model_dump(mode="json"),
            "report_id": str(request.report_id),
            "patch_id": str(draft.patch_id),
            "draft_sha256": draft.draft_sha256,
            "before": _member(deterministic.intent.before).model_dump(mode="json"),
            "after": _member(deterministic.intent.after).model_dump(mode="json"),
            "before_analysis_id": str(deterministic.before_analysis_id),
            "before_analysis_sha256": deterministic.before_analysis_sha256,
            "original_statistical_present": statistical,
            "created_at": TypeAdapter(datetime).dump_python(created_at, mode="json"),
            "deterministic": deterministic_projection.model_dump(mode="json"),
            "forest": forest_projection.model_dump(mode="json") if forest_projection else None,
            "neural": neural_projection.model_dump(mode="json") if neural_projection else None,
            "network": network_projection.model_dump(mode="json") if network_projection else None,
            "validation_blockers": source_evidence_blockers(
                statistical, forest_projection, neural_projection, network_projection
            ),
            "status": "needs_review",
            "formal_qualification": "not_proven",
            "risk_fused": False,
            "calibrated": False,
            "quality_proven": False,
            "approved": False,
            "applied": False,
        }
        proof = ml_json(value)
        if len(proof.encode()) > MAX_SOURCE_EVIDENCE_BYTES:
            raise SourceEvidenceProjectionTooLarge("joint evidence projection exceeds its budget")
        return cls.model_validate(
            value | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}
        )

    def validate_evidence(
        self,
        draft: PatchDraft,
        deterministic: SourceDeterministicRecheck,
        *,
        forest: SourceForestRecheck | None = None,
        neural: SourceMlRecheck | None = None,
        network: SourcePatchReview | None = None,
    ) -> None:
        """Require the exact saved projection, including every child pin, on historical reads."""
        actual = type(self).model_validate(self.model_dump())
        expected = type(self).from_evidence(
            draft,
            actual.request,
            deterministic,
            forest=forest,
            neural=neural,
            network=network,
            created_at=actual.created_at,
        )
        if actual != expected:
            raise ValueError("joint evidence differs from the exact saved child projections")


class SourceEvidenceSummaryV3(Frozen):
    version: Literal["source-evidence-summary-0.3.0"] = "source-evidence-summary-0.3.0"
    report_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    review_sha256: Digest
    created_at: datetime
    selected_kinds: tuple[EvidenceKind, ...] = Field(min_length=1, max_length=4)
    status: Literal["needs_review"] = "needs_review"

    @model_validator(mode="after")
    def ordered_selection(self) -> Self:
        if (
            self.created_at.utcoffset() is None
            or self.selected_kinds
            != tuple(kind for kind in _EVIDENCE_KINDS if kind in self.selected_kinds)
            or self.selected_kinds[0] != "deterministic"
        ):
            raise ValueError("joint summary requires ordered unique selected evidence")
        return self

    @classmethod
    def from_report(cls, report: SourceEvidenceReportV3) -> Self:
        selected: tuple[EvidenceKind, ...] = tuple(
            kind for kind in _EVIDENCE_KINDS if getattr(report, kind) is not None
        )
        return cls(
            report_id=report.report_id,
            patch_id=report.patch_id,
            draft_sha256=report.draft_sha256,
            before_analysis_id=report.before_analysis_id,
            review_sha256=report.review_sha256,
            created_at=report.created_at,
            selected_kinds=selected,
        )


SourceEvidenceRequest = sdk.SourceEvidenceRequest | CreateSourceEvidenceReportV3
SourceEvidenceReportRecord = sdk.SourceEvidenceReportRecord | SourceEvidenceReportV3
SourceEvidenceSummaryRecord = sdk.SourceEvidenceSummaryRecord | SourceEvidenceSummaryV3
_DiscriminatedRequest = Annotated[SourceEvidenceRequest, Field(discriminator="version")]
_REQUEST: TypeAdapter[SourceEvidenceRequest] = TypeAdapter(_DiscriminatedRequest)
_DiscriminatedReport = Annotated[SourceEvidenceReportRecord, Field(discriminator="version")]
_REPORT: TypeAdapter[SourceEvidenceReportRecord] = TypeAdapter(_DiscriminatedReport)


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
    deterministic: SourceDeterministicRecheck,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
    created_at: datetime,
) -> SourceEvidenceReportRecord:
    request = parse_source_evidence_request(request)
    if isinstance(request, CreateSourceEvidenceReportV3):
        return SourceEvidenceReportV3.from_evidence(
            draft,
            request,
            deterministic,
            forest=forest,
            neural=neural,
            network=network,
            created_at=created_at,
        )
    if isinstance(network, SourcePatchVerificationV3):
        raise ValueError("selected network result requires a newer report protocol")
    return sdk.source_evidence_report(
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
    deterministic: SourceDeterministicRecheck,
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
        raise ValueError("joint evidence differs from the exact saved child projections")


def source_evidence_summary(report: SourceEvidenceReportRecord) -> SourceEvidenceSummaryRecord:
    if isinstance(report, SourceEvidenceReportV3):
        return SourceEvidenceSummaryV3.from_report(report)
    return sdk.source_evidence_summary(report)
