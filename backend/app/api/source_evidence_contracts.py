"""Compact immutable composition of existing ordinary-source evidence, without execution."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StrictBool, TypeAdapter, field_validator, model_validator

from app.api.contracts import SnapshotBinding
from app.api.model_patch_review_contracts import StatisticalRecheck
from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import (
    ComparisonVersion,
    SourceDeterministicRecheck,
    SourceDeterministicSide,
)
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck, ml_json, source_ml_fingerprint
from app.api.source_patch_contracts import SourcePatchVerification
from app.verification.batfish import BatfishResult
from app.verification.source_evidence import EvidenceKind, bind_selected_source_evidence
from ml.evaluation.contracts import Count, Digest, Frozen, Label, UnitScore
from ml.inference.change_contracts import SidePrediction
from ml.registry.contracts import TASKS

MAX_SOURCE_EVIDENCE_BYTES = 4 * 1024 * 1024
type BoundedText = Annotated[str, Field(min_length=1, max_length=2048)]
type Blockers = Annotated[tuple[BoundedText, ...], Field(max_length=64)]
_EVIDENCE_KINDS: tuple[EvidenceKind, ...] = ("deterministic", "forest", "neural", "network")


class SourceEvidenceProjectionTooLarge(ValueError):
    """A composed proof exceeds the report budget before storage or audit mutation."""


class SelectedEvidenceRef(Frozen):
    record_id: UUID
    review_sha256: Digest


class CreateSourceEvidenceReport(Frozen):
    version: Literal["source-evidence-request-0.1.0"] = "source-evidence-request-0.1.0"
    report_id: UUID
    draft_sha256: Digest
    deterministic: SelectedEvidenceRef
    forest: SelectedEvidenceRef | None
    neural: SelectedEvidenceRef | None
    network: SelectedEvidenceRef | None


class SourceEvidenceMember(SnapshotBinding):
    canonical_sha256: Digest


class _CompletedEvidence(Frozen):
    record_id: UUID
    review_sha256: Digest
    created_at: datetime
    completed_at: datetime
    validation_blockers: Blockers

    @model_validator(mode="after")
    def chronology(self) -> Self:
        if (
            self.created_at.utcoffset() is None
            or self.completed_at.utcoffset() is None
            or self.completed_at < self.created_at
        ):
            raise ValueError("selected evidence requires aware ordered execution times")
        return self


class SourceEvidenceFindingCounts(Frozen):
    policy: Count
    reference: Count | None
    peer: Count | None

    @classmethod
    def from_side(cls, side: SourceDeterministicSide) -> Self:
        return cls(
            policy=len(side.policy_findings),
            reference=len(side.reference_findings) if side.reference_findings is not None else None,
            peer=len(side.peer_findings) if side.peer_findings is not None else None,
        )


class SourceEvidencePolicyChanges(Frozen):
    introduced: Count
    resolved: Count
    persistent: Count


class SourceDeterministicEvidence(_CompletedEvidence):
    kind: Literal["deterministic"] = "deterministic"
    version: Literal["source-deterministic-recheck-0.1.0"]
    policy_catalog_version: BoundedText
    comparison_version: ComparisonVersion
    reference: SourceEvidenceMember | None
    peer_profile_sha256: Digest | None
    peer_count: int = Field(ge=0, le=20, strict=True)
    before: SourceEvidenceFindingCounts
    after: SourceEvidenceFindingCounts
    policy_changes: SourceEvidencePolicyChanges

    @model_validator(mode="after")
    def selected_scope(self) -> Self:
        if (
            (self.peer_profile_sha256 is not None) != bool(self.peer_count)
            or (self.peer_count != 0 and self.peer_count < 3)
            or self.before.policy != self.policy_changes.resolved + self.policy_changes.persistent
            or self.after.policy != self.policy_changes.introduced + self.policy_changes.persistent
            or (self.comparison_version == "not_selected")
            != (self.reference is None and self.peer_profile_sha256 is None)
            or any(
                (side.reference is not None) != (self.reference is not None)
                or (side.peer is not None) != (self.peer_profile_sha256 is not None)
                for side in (self.before, self.after)
            )
        ):
            raise ValueError("deterministic evidence scope or finding partition differs")
        return self


class SourceForestEvidence(_CompletedEvidence):
    kind: Literal["forest"] = "forest"
    version: Literal["source-forest-recheck-0.1.0"]
    model_id: UUID
    artifact_sha256: Digest
    model_version: BoundedText
    feature_schema_version: BoundedText
    library: Literal["scikit-learn"] = "scikit-learn"
    library_version: BoundedText
    decision_offset: float = Field(ge=-1, le=0, strict=True)
    scores: StatisticalRecheck
    interpretation: Literal["experimental_scores_not_change_validation"] = (
        "experimental_scores_not_change_validation"
    )

    @model_validator(mode="after")
    def numeric_binding(self) -> Self:
        scores = self.scores
        if (scores.model_id, scores.artifact_sha256) != (self.model_id, self.artifact_sha256):
            raise ValueError("Forest projection model differs from its scores")
        for score, decision, prediction in (
            (
                scores.before_score_samples,
                scores.before_decision_function,
                scores.before_prediction,
            ),
            (scores.after_score_samples, scores.after_decision_function, scores.after_prediction),
        ):
            if (
                not -1 <= score <= 0
                or not -1 <= decision <= 1
                or decision != score - self.decision_offset
                or prediction != (-1 if decision < 0 else 1)
            ):
                raise ValueError("Forest projection threshold or score differs")
        return self


class SourceNeuralSideEvidence(Frozen):
    raw_source_sha256: Digest
    sanitized_source_sha256: Digest
    total_lines: int = Field(ge=1, le=10000, strict=True)
    anomaly_score: UnitScore | None
    category_scores: dict[Label, UnitScore] | None = Field(max_length=64)
    severity_scores: dict[Literal["info", "low", "medium", "high", "critical"], UnitScore] | None
    scored_line_count: int = Field(ge=0, le=10000, strict=True)
    embedding_dimensions: int = Field(ge=0, le=1024, strict=True)

    @model_validator(mode="after")
    def dimensions(self) -> Self:
        if self.scored_line_count > self.total_lines or (
            self.severity_scores is not None
            and (
                set(self.severity_scores) != {"info", "low", "medium", "high", "critical"}
                or abs(sum(self.severity_scores.values()) - 1) > 1e-5
            )
        ):
            raise ValueError("neural evidence dimensions differ")
        return self

    @classmethod
    def from_prediction(cls, prediction: SidePrediction) -> Self:
        return cls(
            raw_source_sha256=prediction.raw_source_sha256,
            sanitized_source_sha256=prediction.sanitized_source_sha256,
            total_lines=prediction.total_lines,
            anomaly_score=prediction.anomaly_score,
            category_scores=prediction.category_scores,
            severity_scores=prediction.severity_scores,
            scored_line_count=sum(score is not None for score in prediction.line_scores),
            embedding_dimensions=prediction.embedding_dimensions,
        )


class SourceNeuralEvidence(_CompletedEvidence):
    kind: Literal["neural"] = "neural"
    version: Literal["source-ml-recheck-0.1.0"]
    model_card_version: Literal[
        "config-model-card-0.1.0", "config-model-card-0.2.0", "config-model-card-0.3.0"
    ]
    model_card_sha256: Digest
    model_sha256: Digest
    model_kind: Literal["native", "foundation"]
    training_format: BoundedText
    training_report_sha256: Digest
    encoder_sha256: Digest
    tokenizer_sha256: Digest
    classes: tuple[Label, ...] = Field(min_length=1, max_length=64)
    enabled_heads: dict[str, StrictBool] = Field(min_length=5, max_length=5)
    runtime_torch_version: BoundedText
    sanitization_version: Literal["config-sanitizer-0.1.0"]
    target_semantics: Literal["injected_mutation", "confirmed_anomaly"]
    external_pretraining_exposure: Literal["unknown", "not_applicable"]
    before: SourceNeuralSideEvidence
    after: SourceNeuralSideEvidence
    interpretation: Literal["experimental_scores_not_change_validation"] = (
        "experimental_scores_not_change_validation"
    )

    @model_validator(mode="after")
    def recorded_heads(self) -> Self:
        if set(self.enabled_heads) != TASKS or len(set(self.classes)) != len(self.classes):
            raise ValueError("neural evidence class or head inventory differs")
        for side in (self.before, self.after):
            if (
                self.enabled_heads["anomaly"] != (side.anomaly_score is not None)
                or self.enabled_heads["category"] != (side.category_scores is not None)
                or self.enabled_heads["severity"] != (side.severity_scores is not None)
                or self.enabled_heads["contrastive"] != (side.embedding_dimensions > 0)
                or (not self.enabled_heads["localization"] and side.scored_line_count != 0)
                or (
                    side.category_scores is not None
                    and set(side.category_scores) != set(self.classes)
                )
            ):
                raise ValueError("neural evidence outputs differ from recorded model heads")
        return self


class SourceNetworkEvidence(_CompletedEvidence):
    kind: Literal["network"] = "network"
    version: Literal["source-patch-verification-0.1.0"]
    result: BatfishResult
    # Source network 0.1 never recorded the SDK version. Do not impute today's runtime.
    sdk_version: None = None
    ml_status: Literal["not_run"] = "not_run"
    network_device_count: int = Field(ge=1, le=32, strict=True)


def source_evidence_blockers(
    original_statistical_present: bool,
    forest: SourceForestEvidence | None,
    neural: SourceNeuralEvidence | None,
    network: SourceNetworkEvidence | None,
) -> tuple[str, ...]:
    result = [
        "baseline_approval_not_proven",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
        "individual_engineer_review_required",
        "independent_quality_not_proven",
        "calibration_not_proven",
        "formal_qualification_not_proven",
        "deterministic_quality_not_proven",
    ]
    if forest is None:
        if original_statistical_present:
            result.append("original_statistical_not_selected")
    else:
        result.append("original_statistical_quality_not_proven")
    if neural is None:
        result.append("neural_not_selected")
    else:
        result.extend(
            (
                "change_specific_ml_quality_not_proven",
                "selected_model_independent_quality_not_proven",
            )
        )
    if network is None:
        result.append("network_not_selected")
    else:
        result.append("network_scope_not_overall_formal_qualification")
        if network.result.status != "no_differences_in_scope":
            result.append("formal_scope_not_passed")
        if network.result.cleanup_complete is not True:
            result.append("engine_cleanup_not_confirmed")
    return tuple(result)


class SourceEvidenceReport(Frozen):
    version: Literal["source-evidence-report-0.1.0"] = "source-evidence-report-0.1.0"
    request: CreateSourceEvidenceReport
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
    network: SourceNetworkEvidence | None
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
        request: CreateSourceEvidenceReport,
        deterministic: SourceDeterministicRecheck,
        *,
        forest: SourceForestRecheck | None = None,
        neural: SourceMlRecheck | None = None,
        network: SourcePatchVerification | None = None,
        created_at: datetime,
    ) -> Self:
        """Project integrity-checked records without reading a repository or running detectors."""
        selected = bind_selected_source_evidence(
            draft, deterministic, forest=forest, neural=neural, network=network
        )
        request = CreateSourceEvidenceReport.model_validate(request.model_dump())
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
        network_projection = _network_projection(network) if network is not None else None
        statistical = deterministic.intent.selection.original.statistical_present
        value = {
            "version": "source-evidence-report-0.1.0",
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
        network: SourcePatchVerification | None = None,
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


def _member(member: SnapshotBinding) -> SourceEvidenceMember:
    return SourceEvidenceMember.model_validate(
        member.model_dump(
            include={
                "configuration_id",
                "device_id",
                "source_sha256",
                "created_at",
                "canonical_sha256",
            }
        )
    )


def _deterministic_projection(value: SourceDeterministicRecheck) -> SourceDeterministicEvidence:
    assert value.outcome is not None and value.outcome.report is not None
    report, context = value.outcome.report, value.intent.selection.original.comparison
    return SourceDeterministicEvidence(
        version=value.version,
        record_id=value.recheck_id,
        review_sha256=value.review_sha256,
        created_at=value.intent.created_at,
        completed_at=value.outcome.completed_at,
        validation_blockers=value.validation_blockers,
        policy_catalog_version=report.policy_catalog_version,
        comparison_version=report.comparison_version,
        reference=_member(value.intent.selection.reference)
        if value.intent.selection.reference
        else None,
        peer_profile_sha256=report.peer_profile_sha256,
        peer_count=len(context.peers) if context else 0,
        before=SourceEvidenceFindingCounts.from_side(report.before),
        after=SourceEvidenceFindingCounts.from_side(report.after),
        policy_changes=SourceEvidencePolicyChanges(
            introduced=len(report.policy_changes.introduced),
            resolved=len(report.policy_changes.resolved),
            persistent=len(report.policy_changes.persistent),
        ),
    )


def _forest_projection(value: SourceForestRecheck) -> SourceForestEvidence:
    assert value.outcome is not None and value.outcome.report is not None
    report = value.outcome.report
    return SourceForestEvidence(
        version=value.version,
        record_id=value.recheck_id,
        review_sha256=value.review_sha256,
        created_at=value.intent.created_at,
        completed_at=value.outcome.completed_at,
        validation_blockers=value.validation_blockers,
        model_id=value.model_id,
        artifact_sha256=value.artifact_sha256,
        model_version=report.model.metadata.model_version,
        feature_schema_version=report.model.metadata.feature_schema_version,
        library_version=report.model.metadata.library_version,
        decision_offset=report.model.decision_offset,
        scores=report.scores,
    )


def _neural_projection(value: SourceMlRecheck) -> SourceNeuralEvidence:
    assert value.outcome is not None and value.outcome.report is not None
    report = value.outcome.report
    model = report.before.model
    return SourceNeuralEvidence(
        version=value.version,
        record_id=value.recheck_id,
        review_sha256=value.review_sha256,
        created_at=value.intent.created_at,
        completed_at=value.outcome.completed_at,
        validation_blockers=value.validation_blockers,
        model_card_version=model.version,
        model_card_sha256=source_ml_fingerprint(model),
        model_sha256=model.model_sha256,
        model_kind=model.kind,
        training_format=model.training_format,
        training_report_sha256=model.report_sha256,
        encoder_sha256=model.encoder_sha256,
        tokenizer_sha256=model.tokenizer_sha256,
        classes=model.classes,
        enabled_heads=model.enabled_heads,
        runtime_torch_version=report.before.runtime_torch_version,
        sanitization_version=report.before.sanitization_version,
        target_semantics=model.target_semantics,
        external_pretraining_exposure=model.external_pretraining_exposure,
        before=SourceNeuralSideEvidence.from_prediction(report.before.prediction),
        after=SourceNeuralSideEvidence.from_prediction(report.after.prediction),
    )


def _network_projection(value: SourcePatchVerification) -> SourceNetworkEvidence:
    assert value.outcome is not None
    return SourceNetworkEvidence(
        version=value.version,
        record_id=value.verification_id,
        review_sha256=value.review_sha256,
        created_at=value.intent.created_at,
        completed_at=value.outcome.completed_at,
        validation_blockers=value.validation_blockers,
        result=value.outcome.network_result,
        network_device_count=1 + len(value.intent.companions),
    )


class SourceEvidenceSummary(Frozen):
    version: Literal["source-evidence-summary-0.1.0"] = "source-evidence-summary-0.1.0"
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
    def from_report(cls, report: SourceEvidenceReport) -> Self:
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
