"""Frozen ordinary-source deterministic evidence, without historical detector reruns."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from hashlib import sha256
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import Field, StrictBool, field_validator, model_validator

from app.api.contracts import (
    AnalysisResult,
    ComparisonContext,
    ExpandedComparisonContext,
    MeasuredComparisonContext,
    SnapshotBinding,
)
from app.api.model_patch_contracts import fingerprint
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.detection.baseline import (
    ExpandedPeerEvaluation,
    ExpandedReference,
    ExpectedConfiguration,
    MeasuredPeerEvaluation,
)
from app.domain import Finding
from app.verification.policy_changes import PolicyChanges
from ml.evaluation.contracts import Digest, Frozen

if TYPE_CHECKING:
    from app.detection.baseline.pair import OriginalDeterministicPair

MAX_SOURCE_DETERMINISTIC_BYTES = 4 * 1024 * 1024
type OriginalComparison = ComparisonContext | ExpandedComparisonContext | MeasuredComparisonContext
type ReferenceProjection = ExpectedConfiguration | ExpandedReference
type PeerEvaluation = ExpandedPeerEvaluation | MeasuredPeerEvaluation
type ComparisonVersion = Literal["not_selected", "0.1.0", "0.2.0", "0.3.0"]
_DETECTORS = {"policy_engine", "expected_configuration", "peer_baseline"}


def _json(value: object) -> str:
    """Normalize tuples in untyped saved observations without dropping any fields."""
    return ml_json(value)


def _finding_json(finding: Finding) -> str:
    return _json(finding.model_dump(mode="json"))


def _findings_json(findings: Sequence[Finding]) -> str:
    return _json([finding.model_dump(mode="json") for finding in findings])


def _comparison_version(context: OriginalComparison | None) -> ComparisonVersion:
    if isinstance(context, MeasuredComparisonContext):
        return "0.3.0"
    if isinstance(context, ExpandedComparisonContext):
        return "0.2.0"
    return "0.1.0" if context is not None else "not_selected"


class RunSourceDeterministicRecheck(Frozen):
    version: Literal["source-deterministic-request-0.1.0"] = "source-deterministic-request-0.1.0"
    recheck_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    reference_canonical_sha256: Digest | None
    allow_local_analysis_context: StrictBool = False


class SourceDeterministicMember(SnapshotBinding):
    canonical_sha256: Digest


class OriginalDeterministicContext(Frozen):
    policy_catalog_version: str = Field(min_length=1, max_length=128)
    comparison: OriginalComparison | None
    findings: tuple[Finding, ...] = Field(max_length=10000)
    statistical_present: StrictBool

    @model_validator(mode="after")
    def recorded_scope(self) -> Self:
        versions = {"policy_engine": self.policy_catalog_version}
        context = self.comparison
        if context is not None:
            if context.reference is not None:
                versions["expected_configuration"] = (
                    "expected-config-0.1.0"
                    if isinstance(context, ComparisonContext)
                    else "expected-config-0.2.0"
                )
            if context.peer_baseline is not None:
                versions["peer_baseline"] = context.peer_baseline.model_version
            if isinstance(context, (ExpandedComparisonContext, MeasuredComparisonContext)):
                evaluation = context.peer_evaluation
                peers = tuple(row for row in self.findings if row.detector == "peer_baseline")
                if evaluation is not None and _findings_json(evaluation.findings) != (
                    _findings_json(peers)
                ):
                    raise ValueError("original peer findings differ from the saved report")
        if len({row.finding_id for row in self.findings}) != len(self.findings) or any(
            row.detector not in _DETECTORS
            or row.detector not in versions
            or row.model_version != versions[row.detector]
            for row in self.findings
        ):
            raise ValueError("original deterministic findings differ from their recorded scope")
        return self

    @classmethod
    def from_analysis(cls, analysis: AnalysisResult) -> Self:
        # This projection never evaluates a catalog, comparator, model or risk score.
        return cls(
            policy_catalog_version=analysis.policy_catalog_version,
            comparison=analysis.comparison,
            findings=tuple(row for row in analysis.findings if row.detector in _DETECTORS),
            statistical_present=analysis.statistical is not None,
        )


class SourceDeterministicSelection(Frozen):
    version: Literal["source-deterministic-selection-0.1.0"] = (
        "source-deterministic-selection-0.1.0"
    )
    patch_id: UUID
    draft_sha256: Digest
    before: SnapshotBinding
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    before_analysis_created_at: datetime
    original: OriginalDeterministicContext
    reference: SourceDeterministicMember | None

    @model_validator(mode="after")
    def bound_original(self) -> Self:
        context = self.original.comparison
        reference = context.reference if context is not None else None
        if (
            self.before_analysis_created_at.utcoffset() is None
            or self.before_analysis_created_at < self.before.created_at
            or any(row.device_id != self.before.device_id for row in self.original.findings)
            or (reference is None) != (self.reference is None)
        ):
            raise ValueError("original deterministic selection differs")
        if self.reference is not None:
            assert reference is not None
            if (
                self.reference.model_dump(exclude={"canonical_sha256"}) != reference.model_dump()
                or self.reference.device_id != self.before.device_id
                or self.reference.configuration_id == self.before.configuration_id
                or self.reference.created_at > self.before.created_at
                or any(
                    row.expected.get("reference_id") != str(reference.configuration_id)
                    or row.expected.get("source_sha256") != reference.source_sha256
                    or row.observed.get("source_sha256") != self.before.source_sha256
                    for row in self.original.findings
                    if row.detector == "expected_configuration"
                )
            ):
                raise ValueError("original reference metadata or finding source differs")
        if context is not None and any(
            row.device_id == self.before.device_id
            or row.configuration_id == self.before.configuration_id
            or row.source_sha256 == self.before.source_sha256
            or row.created_at > self.before.created_at
            for row in context.peers
        ):
            raise ValueError("original peer population includes target or future input")
        if isinstance(context, (ExpandedComparisonContext, MeasuredComparisonContext)):
            evaluation = context.peer_evaluation
            if evaluation is not None and (
                evaluation.device_id != self.before.device_id
                or evaluation.source_sha256 != self.before.source_sha256
            ):
                raise ValueError("original peer report belongs to another source")
        return self


class SourceDeterministicIntent(Frozen):
    version: Literal["source-deterministic-intent-0.1.0"] = "source-deterministic-intent-0.1.0"
    patch_id: UUID
    request: RunSourceDeterministicRecheck
    before: SourceDeterministicMember
    after: SourceDeterministicMember
    selection: SourceDeterministicSelection
    reference_projection: ReferenceProjection | None
    created_at: datetime

    @model_validator(mode="after")
    def bindings(self) -> Self:
        old, new, selected, request = self.before, self.after, self.selection, self.request
        if (
            self.created_at.utcoffset() is None
            or not old.created_at <= new.created_at <= self.created_at
            or self.created_at < selected.before_analysis_created_at
            or old.device_id != new.device_id
            or old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or request.allow_local_analysis_context is not True
            or self.patch_id != selected.patch_id
            or request.draft_sha256 != selected.draft_sha256
            or request.before_analysis_id != selected.before_analysis_id
            or request.before_analysis_sha256 != selected.before_analysis_sha256
            or old.model_dump(exclude={"canonical_sha256"}) != selected.before.model_dump()
            or request.reference_canonical_sha256
            != (selected.reference.canonical_sha256 if selected.reference else None)
            or (self.reference_projection is None) != (selected.reference is None)
        ):
            raise ValueError("ordinary deterministic intent differs from its selected context")
        projection, reference = self.reference_projection, selected.reference
        if projection is not None and reference is not None:
            expected_version = (
                "expected-config-0.1.0"
                if isinstance(selected.original.comparison, ComparisonContext)
                else "expected-config-0.2.0"
            )
            if (
                projection.version != expected_version
                or projection.reference_id != str(reference.configuration_id)
                or projection.device_id != reference.device_id
                or projection.source_sha256 != reference.source_sha256
                or reference.configuration_id == new.configuration_id
            ):
                raise ValueError("frozen reference projection differs from its selected snapshot")
        context = selected.original.comparison
        if context is not None and any(
            row.device_id == new.device_id
            or row.configuration_id == new.configuration_id
            or row.source_sha256 == new.source_sha256
            or row.created_at > new.created_at
            for row in context.peers
        ):
            raise ValueError("after source belongs to the original peer population")
        return self


class SourceDeterministicSide(Frozen):
    configuration_id: UUID
    source_sha256: Digest
    policy_findings: tuple[Finding, ...] = Field(max_length=10000)
    reference_findings: tuple[Finding, ...] | None
    peer_findings: tuple[Finding, ...] | None
    peer_evaluation: PeerEvaluation | None

    @model_validator(mode="after")
    def typed_detector_groups(self) -> Self:
        groups = (
            (self.policy_findings, "policy_engine"),
            (self.reference_findings or (), "expected_configuration"),
            (self.peer_findings or (), "peer_baseline"),
        )
        findings = tuple(row for group, _ in groups for row in group)
        if len({row.finding_id for row in findings}) != len(findings) or any(
            row.detector != detector for group, detector in groups for row in group
        ):
            raise ValueError("deterministic side finding inventory differs")
        report = self.peer_evaluation
        if report is not None and (
            self.peer_findings is None
            or _findings_json(report.findings) != _findings_json(self.peer_findings)
            or report.source_sha256 != self.source_sha256
            or report.status != "completed"
        ):
            raise ValueError("deterministic side peer report differs")
        return self


def _semantic_key(finding: Finding) -> str:
    return _json([finding.category, finding.severity.value, finding.observed, finding.expected])


def _validate_policy_changes(
    changes: PolicyChanges, before: Sequence[Finding], after: Sequence[Finding]
) -> None:
    old = (*changes.resolved, *(pair.before for pair in changes.persistent))
    new = (*changes.introduced, *(pair.after for pair in changes.persistent))
    if (
        Counter(map(_finding_json, old)) != Counter(map(_finding_json, before))
        or Counter(map(_finding_json, new)) != Counter(map(_finding_json, after))
        or any(
            _semantic_key(pair.before) != _semantic_key(pair.after) for pair in changes.persistent
        )
        or set(map(_semantic_key, changes.resolved)) & set(map(_semantic_key, changes.introduced))
    ):
        raise ValueError("policy change partition differs from the complete finding multisets")


class SourceDeterministicReport(Frozen):
    version: Literal["source-deterministic-report-0.1.0"] = "source-deterministic-report-0.1.0"
    policy_catalog_version: str = Field(min_length=1, max_length=128)
    comparison_version: ComparisonVersion
    before: SourceDeterministicSide
    after: SourceDeterministicSide
    reference_projection: ReferenceProjection | None
    peer_profile_sha256: Digest | None
    policy_changes: PolicyChanges

    @model_validator(mode="after")
    def policy_partition(self) -> Self:
        policy = self.before.policy_findings + self.after.policy_findings
        if any(row.model_version != self.policy_catalog_version for row in policy) or (
            len({row.device_id for row in policy}) > 1
        ):
            raise ValueError("policy changes require the recorded catalog and one device")
        _validate_policy_changes(
            self.policy_changes, self.before.policy_findings, self.after.policy_findings
        )
        return self

    @classmethod
    def from_pair(cls, intent: SourceDeterministicIntent, pair: OriginalDeterministicPair) -> Self:
        from app.detection.baseline.pair import DeterministicSide, OriginalDeterministicPair

        if not isinstance(pair, OriginalDeterministicPair):
            raise ValueError("deterministic result requires the typed library pair")

        def side(member: SourceDeterministicMember, source: object) -> SourceDeterministicSide:
            # The input is the actual library dataclass, not a fabricated historical rerun.
            if not isinstance(source, DeterministicSide):
                raise ValueError("deterministic result requires a typed library side")
            return SourceDeterministicSide(
                configuration_id=member.configuration_id,
                source_sha256=member.source_sha256,
                policy_findings=source.policy_findings,
                reference_findings=source.reference_findings,
                peer_findings=source.peer_findings,
                peer_evaluation=source.peer_evaluation,
            )

        context = intent.selection.original.comparison
        report = cls(
            policy_catalog_version=intent.selection.original.policy_catalog_version,
            comparison_version=_comparison_version(context),
            before=side(intent.before, pair.before),
            after=side(intent.after, pair.after),
            reference_projection=pair.reference,
            peer_profile_sha256=(
                fingerprint(context.peer_baseline)
                if context is not None and context.peer_baseline is not None
                else None
            ),
            policy_changes=pair.policy_changes,
        )
        report.validate_intent(intent)
        return report

    def validate_intent(self, intent: SourceDeterministicIntent) -> None:
        original = intent.selection.original
        context = original.comparison
        profile = context.peer_baseline if context is not None else None
        if (
            self.policy_catalog_version != original.policy_catalog_version
            or self.comparison_version != _comparison_version(context)
            or self.reference_projection != intent.reference_projection
            or self.peer_profile_sha256 != (fingerprint(profile) if profile else None)
        ):
            raise ValueError("deterministic report catalog, reference or profile pin differs")
        for side, member in ((self.before, intent.before), (self.after, intent.after)):
            _validate_side(side, member, context, intent.reference_projection)
        before = (
            self.before.policy_findings
            + (self.before.reference_findings or ())
            + (self.before.peer_findings or ())
        )
        if _findings_json(before) != _findings_json(original.findings):
            raise ValueError("deterministic result differs from all original before finding fields")
        if isinstance(context, (ExpandedComparisonContext, MeasuredComparisonContext)):
            actual, saved = self.before.peer_evaluation, context.peer_evaluation
            if _json(actual.model_dump(mode="json") if actual else None) != _json(
                saved.model_dump(mode="json") if saved else None
            ):
                raise ValueError(
                    "deterministic result differs from the original before peer report"
                )


def _validate_side(
    side: SourceDeterministicSide,
    member: SourceDeterministicMember,
    context: OriginalComparison | None,
    reference: ReferenceProjection | None,
) -> None:
    selected_peers = context is not None and context.peer_baseline is not None
    if (
        (side.configuration_id, side.source_sha256)
        != (member.configuration_id, member.source_sha256)
        or (side.reference_findings is not None) != (reference is not None)
        or (side.peer_findings is not None) != selected_peers
    ):
        raise ValueError("deterministic result source or not-selected scope differs")
    for group in (side.policy_findings, side.reference_findings or (), side.peer_findings or ()):
        if any(row.device_id != member.device_id for row in group):
            raise ValueError("deterministic finding belongs to another device")
    if reference is not None and any(
        row.model_version != reference.version
        or row.expected.get("reference_id") != reference.reference_id
        or row.expected.get("source_sha256") != reference.source_sha256
        or row.observed.get("source_sha256") != side.source_sha256
        for row in side.reference_findings or ()
    ):
        raise ValueError("deterministic reference finding source differs")
    if not selected_peers:
        if side.peer_evaluation is not None:
            raise ValueError("unselected peers cannot retain a report")
        return
    assert context is not None and context.peer_baseline is not None
    if any(
        row.model_version != context.peer_baseline.model_version for row in side.peer_findings or ()
    ):
        raise ValueError("deterministic peer finding version differs")
    if isinstance(context, (ExpandedComparisonContext, MeasuredComparisonContext)):
        report = side.peer_evaluation
        expected_type = (
            MeasuredPeerEvaluation
            if isinstance(context, MeasuredComparisonContext)
            else ExpandedPeerEvaluation
        )
        if not isinstance(report, expected_type) or report.device_id != member.device_id:
            raise ValueError("deterministic peer report version or device differs")
        # These constructors validate only recorded profile/report data, never compare sources.
        type(context).model_validate(
            context.model_dump(mode="json") | {"peer_evaluation": report.model_dump(mode="json")}
        )
    elif side.peer_evaluation is not None:
        raise ValueError("legacy peer result cannot claim a separate evaluation")
    else:
        features = {
            "baseline." + feature.field.value + "_deviation": feature
            for feature in context.peer_baseline.features
        }
        for finding in side.peer_findings or ():
            feature = features.get(finding.category)
            if feature is None or (
                _json(finding.expected)
                != _json(
                    {
                        feature.field.value: feature.expected,
                        "peer_support_count": feature.support_count,
                        "peer_sample_count": feature.sample_count,
                    }
                )
                or finding.confidence != feature.support_ratio
                or finding.anomaly_score != feature.support_ratio
            ):
                raise ValueError("legacy peer finding differs from its original complete profile")


class SourceDeterministicOutcome(Frozen):
    version: Literal["source-deterministic-outcome-0.1.0"] = "source-deterministic-outcome-0.1.0"
    recheck_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    execution_status: Literal["completed", "failed"]
    report: SourceDeterministicReport | None = None
    failure_reason: Literal["original_context_or_deterministic_result_unavailable"] | None = None

    @model_validator(mode="after")
    def state(self) -> Self:
        if (
            self.completed_at.utcoffset() is None
            or (self.execution_status == "completed") != (self.report is not None)
            or (self.execution_status == "failed") != (self.failure_reason is not None)
        ):
            raise ValueError("deterministic outcome state differs")
        return self


def deterministic_blockers(
    original: OriginalDeterministicContext, outcome: SourceDeterministicOutcome | None
) -> tuple[str, ...]:
    result: tuple[str, ...] = (
        "formal_verification_not_run",
        "deterministic_evidence_not_combined_with_qualified_verification",
        "deterministic_quality_not_proven",
        "baseline_approval_not_proven",
        "individual_engineer_review_required",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
    )
    if original.statistical_present:
        result += ("original_statistical_not_rerun",)
    if outcome is None:
        return (*result, "deterministic_execution_unknown")
    if outcome.execution_status == "failed":
        return (*result, "original_deterministic_unavailable")
    return result


class SourceDeterministicRecheck(Frozen):
    version: Literal["source-deterministic-recheck-0.1.0"] = "source-deterministic-recheck-0.1.0"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    reference_canonical_sha256: Digest | None
    intent: SourceDeterministicIntent
    outcome: SourceDeterministicOutcome | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    validation_blockers: tuple[str, ...]
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_DETERMINISTIC_BYTES, repr=False)
    review_sha256: Digest
    status: Literal["needs_review"] = "needs_review"
    formal_verification: Literal["not_run"] = "not_run"
    risk_fused: Literal[False] = False
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator(
        "risk_fused", "calibrated", "quality_proven", "approved", "applied", mode="before"
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("deterministic evidence cannot promote safety, quality or approval")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        intent, outcome, request = self.intent, self.outcome, self.intent.request
        if (
            (
                self.recheck_id,
                self.patch_id,
                self.draft_sha256,
                self.before_analysis_id,
                self.before_analysis_sha256,
                self.reference_canonical_sha256,
            )
            != (
                request.recheck_id,
                intent.patch_id,
                request.draft_sha256,
                request.before_analysis_id,
                request.before_analysis_sha256,
                request.reference_canonical_sha256,
            )
            or self.execution_status != (outcome.execution_status if outcome else "pending_unknown")
            or self.validation_blockers
            != deterministic_blockers(intent.selection.original, outcome)
        ):
            raise ValueError("deterministic recheck projection differs")
        if outcome is not None:
            if (
                outcome.recheck_id != self.recheck_id
                or outcome.intent_sha256 != source_ml_fingerprint(intent)
                or outcome.completed_at < intent.created_at
            ):
                raise ValueError("deterministic outcome belongs to a different intent")
            if outcome.report is not None:
                outcome.report.validate_intent(intent)
        expected = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            self.review_json != expected
            or len(expected.encode()) > MAX_SOURCE_DETERMINISTIC_BYTES
            or self.review_sha256 != sha256(expected.encode()).hexdigest()
        ):
            raise ValueError("deterministic review proof differs")
        return self

    @classmethod
    def from_records(
        cls, intent: SourceDeterministicIntent, outcome: SourceDeterministicOutcome | None
    ) -> Self:
        request = intent.request
        fields = {
            "version": "source-deterministic-recheck-0.1.0",
            "recheck_id": str(request.recheck_id),
            "patch_id": str(intent.patch_id),
            "draft_sha256": request.draft_sha256,
            "before_analysis_id": str(request.before_analysis_id),
            "before_analysis_sha256": request.before_analysis_sha256,
            "reference_canonical_sha256": request.reference_canonical_sha256,
            "intent": intent.model_dump(mode="json"),
            "outcome": outcome.model_dump(mode="json") if outcome else None,
            "execution_status": outcome.execution_status if outcome else "pending_unknown",
            "validation_blockers": deterministic_blockers(intent.selection.original, outcome),
            "status": "needs_review",
            "formal_verification": "not_run",
            "risk_fused": False,
            "calibrated": False,
            "quality_proven": False,
            "approved": False,
            "applied": False,
        }
        proof = ml_json(fields)
        return cls.model_validate(
            fields | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}
        )


class SourceDeterministicSummary(Frozen):
    version: Literal["source-deterministic-summary-0.1.0"] = "source-deterministic-summary-0.1.0"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    review_sha256: Digest
    created_at: datetime
    completed_at: datetime | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    status: Literal["needs_review"] = "needs_review"

    @classmethod
    def from_recheck(cls, value: SourceDeterministicRecheck) -> Self:
        return cls(
            recheck_id=value.recheck_id,
            patch_id=value.patch_id,
            draft_sha256=value.draft_sha256,
            before_analysis_id=value.before_analysis_id,
            review_sha256=value.review_sha256,
            created_at=value.intent.created_at,
            completed_at=value.outcome.completed_at if value.outcome else None,
            execution_status=value.execution_status,
        )
