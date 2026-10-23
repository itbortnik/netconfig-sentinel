"""Pure experimental AFTER-side priority over exactly selected immutable evidence."""

from __future__ import annotations

from collections.abc import Sequence
from math import isfinite
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StrictBool, field_validator, model_validator

from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import SourceDeterministicRecheck
from app.api.source_evidence_contracts import SourceEvidenceMember
from app.api.source_evidence_direction_contracts import (
    SourceEvidenceReportRecord,
    parse_source_evidence_report_json,
    validate_source_evidence_report,
)
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck
from app.api.source_patch_direction_contracts import (
    SourcePatchReview,
    SourcePatchVerificationV3,
    parse_source_patch_review,
)
from app.domain import Finding, Severity
from app.verification.batfish import BatfishResult
from app.verification.reachability_impact import BatfishDirectionalExecution
from ml.evaluation.contracts import Digest, Frozen, Label, UnitScore

type PrioritySource = Literal["policy", "peer_group", "statistical", "transformer", "verification"]
type PriorityBand = Literal["low", "medium", "high", "critical"]
type PriorityReason = Literal[
    "available",
    "not_selected",
    "peer_context_unavailable",
    "neural_anomaly_head_disabled",
    "legacy_network_protocol",
    "network_adverse_evidence_unavailable",
]
type ChildKind = Literal["deterministic", "forest", "neural", "network"]
type ChildVersion = Literal[
    "source-deterministic-recheck-0.1.0",
    "source-forest-recheck-0.1.0",
    "source-ml-recheck-0.1.0",
    "source-patch-verification-0.1.0",
    "source-patch-verification-0.2.0",
    "source-patch-verification-0.3.0",
]
type NetworkVersion = Literal[
    "source-patch-verification-0.1.0",
    "source-patch-verification-0.2.0",
    "source-patch-verification-0.3.0",
]
type SignedUnit = Annotated[float, Field(strict=True, ge=-1, le=1)]
type NegativeUnit = Annotated[float, Field(strict=True, ge=-1, le=0)]
type ShortText = Annotated[str, Field(min_length=1, max_length=128)]

PRIORITY_SOURCES: tuple[PrioritySource, ...] = (
    "policy",
    "peer_group",
    "statistical",
    "transformer",
    "verification",
)
SOURCE_PRIORITY_PROFILE = "source-priority-profile-0.1.0"
SOURCE_PRIORITY_LIMITATIONS = (
    "This unitless engineering priority is not calibrated risk, probability, detector "
    "severity or detector confidence.",
    "Unavailable source weights are redistributed only within the recorded availability "
    "mask; partial coverage suppresses the aggregate. Completed zero does not establish "
    "overall safety.",
    "Forest normalization and confidence proxy are engineering operations; no new Finding "
    "is asserted.",
    "Neural values retain supported classes and injected-mutation or confirmed-anomaly "
    "target semantics; other classes are not qualified.",
    "Scoped differential examples use common active ingress locations and source IP "
    "inference from the after snapshot; they do not prove whole-network safety or formal "
    "qualification.",
    "The candidate after-side score and raw model outputs do not establish paired "
    "quality, a ranking delta or comparable scores across availability masks.",
    "The profile weights and priority bands at 0.25, 0.50 and 0.80 have not been "
    "calibrated or independently qualified.",
    "No model or verifier is rerun, and no quality, individual identity, approval or "
    "application is established.",
)
_WEIGHTS: dict[PrioritySource, float] = {
    "policy": 0.35,
    "peer_group": 0.15,
    "statistical": 0.10,
    "transformer": 0.10,
    "verification": 0.30,
}
_SEVERITY = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.50,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.00,
}
_KINDS: tuple[ChildKind, ...] = ("deterministic", "forest", "neural", "network")


class PriorityEvidenceRef(Frozen):
    kind: ChildKind
    version: ChildVersion
    record_id: UUID
    review_sha256: Digest

    @model_validator(mode="after")
    def kind_version(self) -> Self:
        prefix = {
            "deterministic": "source-deterministic-recheck-",
            "forest": "source-forest-recheck-",
            "neural": "source-ml-recheck-",
            "network": "source-patch-verification-",
        }[self.kind]
        if not self.version.startswith(prefix):
            raise ValueError("selected child kind and version differ")
        return self


class PriorityFinding(Frozen):
    finding_id: UUID
    severity: Severity
    confidence: UnitScore
    anomaly_score: UnitScore

    @property
    def priority_score(self) -> float:
        return max(_SEVERITY[self.severity], self.anomaly_score) * self.confidence


class FindingPriorityObservation(Frozen):
    kind: Literal["findings"] = "findings"
    detector: Literal["policy_engine", "peer_baseline"]
    finding_count: int = Field(strict=True, ge=0, le=10000)
    strongest: PriorityFinding | None
    critical_policy_present: StrictBool

    @model_validator(mode="after")
    def inventory(self) -> Self:
        if (self.finding_count == 0) != (self.strongest is None):
            raise ValueError("finding count differs from the strongest observation")
        if self.critical_policy_present and (
            self.detector != "policy_engine" or not self.finding_count
        ):
            raise ValueError("critical policy observation requires a policy inventory")
        if self.detector == "policy_engine" and self.strongest is not None:
            if self.strongest.severity == Severity.CRITICAL and not self.critical_policy_present:
                raise ValueError("a strongest critical policy cannot lose its guardrail")
            if self.finding_count == 1 and self.critical_policy_present != (
                self.strongest.severity == Severity.CRITICAL
            ):
                raise ValueError("single policy observation has inconsistent critical status")
        return self

    @property
    def priority_score(self) -> float:
        return self.strongest.priority_score if self.strongest is not None else 0.0


def _normalize(raw: float, minimum: float, maximum: float) -> float:
    # Exactly the existing Isolation Forest _normalize_score formula, without loading an estimator.
    width = maximum - minimum
    if width <= 0.0:
        return 1.0 if raw > maximum else 0.5
    return min(1.0, max(0.0, (raw - minimum) / width))


class ForestPriorityObservation(Frozen):
    kind: Literal["forest"] = "forest"
    model_id: UUID
    artifact_sha256: Digest
    model_version: ShortText
    after_score_samples: NegativeUnit
    after_decision_function: SignedUnit
    after_prediction: Literal[-1, 1]
    decision_offset: NegativeUnit
    training_sample_count: int = Field(strict=True, ge=2, le=1000000)
    training_score_min: UnitScore
    training_score_max: UnitScore
    candidate_parser_confidence: UnitScore
    raw_anomaly_score: UnitScore
    normalized_anomaly: UnitScore
    proxy_confidence: UnitScore
    interpretation: Literal["retained_forest_numeric_proxy_not_new_finding"] = (
        "retained_forest_numeric_proxy_not_new_finding"
    )

    @field_validator("after_prediction", mode="before")
    @classmethod
    def integer_prediction(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Forest prediction requires an integer")
        return value

    @model_validator(mode="after")
    def numeric_consistency(self) -> Self:
        if (
            self.training_score_min > self.training_score_max
            or self.after_decision_function != self.after_score_samples - self.decision_offset
            or self.after_prediction != (-1 if self.after_decision_function < 0 else 1)
            or self.raw_anomaly_score != -self.after_score_samples
            or self.normalized_anomaly
            != _normalize(self.raw_anomaly_score, self.training_score_min, self.training_score_max)
            or self.proxy_confidence
            != min(self.candidate_parser_confidence, self.training_sample_count / 50.0, 1.0)
        ):
            raise ValueError("Forest proxy differs from retained numeric observations")
        return self

    @property
    def priority_score(self) -> float:
        if self.after_prediction == 1:
            return 0.0
        return max(0.5, self.normalized_anomaly) * self.proxy_confidence


class NeuralPriorityObservation(Frozen):
    kind: Literal["neural"] = "neural"
    model_sha256: Digest
    target_semantics: Literal["injected_mutation", "confirmed_anomaly"]
    classes: tuple[Label, ...] = Field(min_length=1, max_length=64)
    anomaly_head_enabled: StrictBool
    anomaly_score: UnitScore | None
    interpretation: Literal["retained_uncalibrated_anomaly_head"] = (
        "retained_uncalibrated_anomaly_head"
    )

    @model_validator(mode="after")
    def enabled_anomaly(self) -> Self:
        if len(set(self.classes)) != len(self.classes) or self.anomaly_head_enabled != (
            self.anomaly_score is not None
        ):
            raise ValueError("neural component differs from recorded anomaly head or classes")
        return self


class NetworkPriorityObservation(Frozen):
    kind: Literal["verification"] = "verification"
    protocol_version: NetworkVersion
    result: BatfishResult
    execution: BatfishDirectionalExecution | None

    @model_validator(mode="after")
    def exact_execution(self) -> Self:
        if (self.protocol_version == "source-patch-verification-0.3.0") != (
            self.execution is not None
        ):
            raise ValueError("network protocol differs from directional observation")
        if self.execution is not None:
            # Revalidate nested public model instances as well as the result equality.
            actual = BatfishDirectionalExecution.model_validate(self.execution.model_dump())
            if actual.result != self.result:
                raise ValueError("network result differs from directional execution")
        return self

    @property
    def scoped_loss(self) -> bool:
        return (
            self.execution is not None
            and self.result.cleanup_complete is True
            and self.execution.reachability_impact.state == "observed"
            and self.execution.reachability_impact.direction
            in {"loss_found", "loss_and_gain_found"}
        )


type PriorityObservation = Annotated[
    FindingPriorityObservation
    | ForestPriorityObservation
    | NeuralPriorityObservation
    | NetworkPriorityObservation,
    Field(discriminator="kind"),
]


class SourcePriorityComponent(Frozen):
    source: PrioritySource
    status: Literal["completed", "unavailable"]
    reason: PriorityReason
    evidence: PriorityEvidenceRef | None
    observation: PriorityObservation | None
    raw_score: UnitScore | None
    configured_weight: UnitScore
    effective_weight: UnitScore
    contribution: UnitScore | None

    @model_validator(mode="after")
    def observed_score(self) -> Self:
        if self.configured_weight != _WEIGHTS[self.source]:
            raise ValueError("component configured weight differs from the fixed profile")
        raw, reason = _component_value(self.source, self.evidence, self.observation)
        if (self.raw_score, self.reason, self.status) != (
            raw,
            reason,
            "completed" if raw is not None else "unavailable",
        ):
            raise ValueError("component score or availability differs from its observation")
        if self.raw_score is None and (self.effective_weight != 0 or self.contribution is not None):
            raise ValueError("unavailable sources cannot contribute a healthy zero")
        if self.contribution is not None and (
            self.raw_score is None or self.contribution != self.raw_score * self.effective_weight
        ):
            raise ValueError("component contribution differs from score and weight")
        if self.contribution is None and self.effective_weight != 0:
            raise ValueError("suppressed component retains a nonzero weight")
        return self


class PriorityGuardrail(Frozen):
    kind: Literal["critical_policy", "observed_scoped_loss"]
    floor: UnitScore

    @model_validator(mode="after")
    def fixed_floor(self) -> Self:
        if self.floor != (0.90 if self.kind == "critical_policy" else 0.95):
            raise ValueError("guardrail floor differs from the fixed profile")
        return self


class SourcePriorityComposition(Frozen):
    version: Literal["source-priority-composition-0.1.0"] = "source-priority-composition-0.1.0"
    profile_version: Literal["source-priority-profile-0.1.0"] = "source-priority-profile-0.1.0"
    side: Literal["after"] = "after"
    report_id: UUID
    report_sha256: Digest
    report_version: Literal[
        "source-evidence-report-0.1.0",
        "source-evidence-report-0.2.0",
        "source-evidence-report-0.3.0",
    ]
    patch_id: UUID
    draft_sha256: Digest
    before: SourceEvidenceMember
    after: SourceEvidenceMember
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    selected_evidence: tuple[PriorityEvidenceRef, ...] = Field(min_length=1, max_length=4)
    coverage: Literal["supported_complete", "partial"]
    candidate_parser_confidence: UnitScore
    components: tuple[SourcePriorityComponent, ...] = Field(min_length=5, max_length=5)
    availability_mask: tuple[PrioritySource, ...] = Field(max_length=5)
    status: Literal["completed", "unavailable"]
    score: UnitScore | None
    band: PriorityBand | None
    applicable_guardrails: tuple[PriorityGuardrail, ...] = Field(max_length=2)
    applied_guardrails: tuple[PriorityGuardrail, ...] = Field(max_length=2)
    review_status: Literal["needs_review"] = "needs_review"
    formal_qualification: Literal["not_proven"] = "not_proven"
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    limitations: tuple[str, ...] = SOURCE_PRIORITY_LIMITATIONS

    @field_validator(
        "calibrated",
        "quality_proven",
        "individual_identity_verified",
        "approved",
        "applied",
        mode="before",
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("experimental priority cannot promote quality or approval")
        return value

    @model_validator(mode="after")
    def complete_profile(self) -> Self:
        if tuple(row.source for row in self.components) != PRIORITY_SOURCES:
            raise ValueError("priority must contain the five ordered fixed-profile sources")
        kinds = tuple(row.kind for row in self.selected_evidence)
        if kinds != tuple(kind for kind in _KINDS if kind in kinds) or kinds[0] != "deterministic":
            raise ValueError("selected evidence must be ordered, unique and include deterministic")
        refs = {row.kind: row for row in self.selected_evidence}
        for row in self.components:
            kind = _source_kind(row.source)
            if row.evidence != refs.get(kind):
                raise ValueError("component evidence differs from selected child references")
            if isinstance(row.observation, ForestPriorityObservation) and (
                row.observation.candidate_parser_confidence != self.candidate_parser_confidence
            ):
                raise ValueError("Forest confidence proxy differs from candidate parser coverage")
        expected_mask = tuple(row.source for row in self.components if row.status == "completed")
        expected_guardrails = _guardrails(self.components)
        if (
            self.availability_mask != expected_mask
            or self.applicable_guardrails != expected_guardrails
        ):
            raise ValueError("availability mask or applicable guardrails differ from observations")
        completed = self.coverage == "supported_complete"
        total = sum(row.configured_weight for row in self.components if row.status == "completed")
        if not total or (self.status == "completed") != completed:
            raise ValueError("aggregate status differs from supported coverage")
        aggregate = 0.0
        for row in self.components:
            weight = (
                row.configured_weight / total if completed and row.raw_score is not None else 0.0
            )
            contribution = (
                row.raw_score * weight if completed and row.raw_score is not None else None
            )
            if (row.effective_weight, row.contribution) != (weight, contribution):
                raise ValueError("effective weight or contribution differs from availability")
            if contribution is not None:
                aggregate += contribution
        score = (
            min(1.0, max((aggregate, *(row.floor for row in expected_guardrails))))
            if completed
            else None
        )
        if (self.score, self.band, self.applied_guardrails) != (
            score,
            _band(score) if score is not None else None,
            expected_guardrails if completed else (),
        ):
            raise ValueError("priority score, band or applied guardrails differ from components")
        if self.limitations != SOURCE_PRIORITY_LIMITATIONS:
            raise ValueError("priority method limitations differ")
        if completed and self.candidate_parser_confidence != 1.0:
            raise ValueError("complete coverage requires complete candidate parser confidence")
        if self.before.device_id != self.after.device_id or (
            self.before.configuration_id == self.after.configuration_id
            or self.before.source_sha256 == self.after.source_sha256
            or self.before.created_at > self.after.created_at
        ):
            raise ValueError("priority target pair differs")
        return self


def _source_kind(source: PrioritySource) -> ChildKind:
    kinds: dict[PrioritySource, ChildKind] = {
        "policy": "deterministic",
        "peer_group": "deterministic",
        "statistical": "forest",
        "transformer": "neural",
        "verification": "network",
    }
    return kinds[source]


def _component_value(
    source: PrioritySource,
    evidence: PriorityEvidenceRef | None,
    observation: PriorityObservation | None,
) -> tuple[float | None, PriorityReason]:
    kind = _source_kind(source)
    if evidence is None:
        if observation is not None or source in {"policy", "peer_group"}:
            raise ValueError("component observation requires its selected child")
        return None, "not_selected"
    if evidence.kind != kind:
        raise ValueError("component source differs from child kind")
    if source in {"policy", "peer_group"}:
        if observation is None and source == "peer_group":
            return None, "peer_context_unavailable"
        if not isinstance(observation, FindingPriorityObservation) or observation.detector != (
            "policy_engine" if source == "policy" else "peer_baseline"
        ):
            raise ValueError("finding component requires its exact detector observation")
        return observation.priority_score, "available"
    if source == "statistical":
        if not isinstance(observation, ForestPriorityObservation):
            raise ValueError("statistical component requires retained Forest numeric metadata")
        return observation.priority_score, "available"
    if source == "transformer":
        if not isinstance(observation, NeuralPriorityObservation):
            raise ValueError("transformer component requires retained neural metadata")
        if not observation.anomaly_head_enabled:
            return None, "neural_anomaly_head_disabled"
        return observation.anomaly_score, "available"
    if (
        not isinstance(observation, NetworkPriorityObservation)
        or observation.protocol_version != evidence.version
    ):
        raise ValueError("verification component requires its exact selected network protocol")
    if observation.execution is None:
        return None, "legacy_network_protocol"
    if observation.scoped_loss:
        return 1.0, "available"
    return None, "network_adverse_evidence_unavailable"


def _guardrails(components: tuple[SourcePriorityComponent, ...]) -> tuple[PriorityGuardrail, ...]:
    rails = []
    for row in components:
        observation = row.observation
        if (
            isinstance(observation, FindingPriorityObservation)
            and observation.critical_policy_present
        ):
            rails.append(PriorityGuardrail(kind="critical_policy", floor=0.90))
        if isinstance(observation, NetworkPriorityObservation) and observation.scoped_loss:
            rails.append(PriorityGuardrail(kind="observed_scoped_loss", floor=0.95))
    return tuple(rails)


def _band(score: float) -> PriorityBand:
    return (
        "critical"
        if score >= 0.80
        else "high"
        if score >= 0.50
        else "medium"
        if score >= 0.25
        else "low"
    )


def _findings(
    rows: Sequence[Finding], detector: Literal["policy_engine", "peer_baseline"]
) -> FindingPriorityObservation:
    strongest = (
        min(
            rows,
            key=lambda row: (
                -max(_SEVERITY[row.severity], row.anomaly_score) * row.confidence,
                str(row.finding_id),
            ),
        )
        if rows
        else None
    )
    return FindingPriorityObservation(
        detector=detector,
        finding_count=len(rows),
        strongest=PriorityFinding.model_validate(
            strongest.model_dump(include={"finding_id", "severity", "confidence", "anomaly_score"})
        )
        if strongest
        else None,
        critical_policy_present=detector == "policy_engine"
        and any(row.severity == Severity.CRITICAL for row in rows),
    )


def _strict_number(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value):
        raise ValueError("priority inputs require finite numeric values without boolean coercion")


def compose_source_priority(
    draft: PatchDraft,
    report: SourceEvidenceReportRecord,
    deterministic: SourceDeterministicRecheck,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
) -> SourcePriorityComposition:
    """Validate complete historical bindings before deriving any experimental priority."""
    _strict_number(draft.diff.after.parser_confidence)
    if deterministic.outcome is not None and deterministic.outcome.report is not None:
        for row in (
            *deterministic.outcome.report.after.policy_findings,
            *(deterministic.outcome.report.after.peer_findings or ()),
        ):
            _strict_number(row.confidence)
            _strict_number(row.anomaly_score)
    draft = PatchDraft.model_validate(draft.model_dump(warnings=False))
    report = parse_source_evidence_report_json(report.model_dump_json(warnings=False))
    deterministic = SourceDeterministicRecheck.model_validate(
        deterministic.model_dump(warnings=False)
    )
    forest = (
        SourceForestRecheck.model_validate(forest.model_dump(warnings=False)) if forest else None
    )
    neural = SourceMlRecheck.model_validate(neural.model_dump(warnings=False)) if neural else None
    network = parse_source_patch_review(network) if network else None
    validate_source_evidence_report(
        report, draft, deterministic, forest=forest, neural=neural, network=network
    )
    assert deterministic.outcome is not None and deterministic.outcome.report is not None
    selected = tuple(
        PriorityEvidenceRef(
            kind=kind,
            version=getattr(report, kind).version,
            record_id=getattr(report, kind).record_id,
            review_sha256=getattr(report, kind).review_sha256,
        )
        for kind in _KINDS
        if getattr(report, kind) is not None
    )
    refs = {row.kind: row for row in selected}
    after = deterministic.outcome.report.after
    observations: dict[PrioritySource, PriorityObservation | None] = {
        "policy": _findings(after.policy_findings, "policy_engine"),
        "peer_group": _findings(after.peer_findings, "peer_baseline")
        if after.peer_findings is not None
        else None,
        "statistical": None,
        "transformer": None,
        "verification": None,
    }
    if forest is not None:
        assert forest.outcome is not None and forest.outcome.report is not None
        model, scores = forest.outcome.report.model, forest.outcome.report.scores
        raw = -scores.after_score_samples
        observations["statistical"] = ForestPriorityObservation(
            model_id=model.model_id,
            artifact_sha256=model.artifact_sha256,
            model_version=model.metadata.model_version,
            after_score_samples=scores.after_score_samples,
            after_decision_function=scores.after_decision_function,
            after_prediction=scores.after_prediction,
            decision_offset=model.decision_offset,
            training_sample_count=model.metadata.sample_count,
            training_score_min=model.metadata.training_score_min,
            training_score_max=model.metadata.training_score_max,
            candidate_parser_confidence=draft.diff.after.parser_confidence,
            raw_anomaly_score=raw,
            normalized_anomaly=_normalize(
                raw, model.metadata.training_score_min, model.metadata.training_score_max
            ),
            proxy_confidence=min(
                draft.diff.after.parser_confidence, model.metadata.sample_count / 50.0, 1.0
            ),
        )
    if neural is not None:
        assert neural.outcome is not None and neural.outcome.report is not None
        side = neural.outcome.report.after
        observations["transformer"] = NeuralPriorityObservation(
            model_sha256=side.model.model_sha256,
            target_semantics=side.model.target_semantics,
            classes=side.model.classes,
            anomaly_head_enabled=side.model.enabled_heads["anomaly"],
            anomaly_score=side.prediction.anomaly_score,
        )
    if network is not None:
        assert network.outcome is not None
        observations["verification"] = NetworkPriorityObservation(
            protocol_version=network.version,
            result=network.outcome.network_result,
            execution=network.outcome.network_execution
            if isinstance(network, SourcePatchVerificationV3) and network.outcome is not None
            else None,
        )
    values = {
        source: _component_value(source, refs.get(_source_kind(source)), observations[source])
        for source in PRIORITY_SOURCES
    }
    mask = tuple(source for source in PRIORITY_SOURCES if values[source][0] is not None)
    total = sum(_WEIGHTS[source] for source in mask)
    complete = draft.diff.coverage == "supported_complete"
    components = []
    for source in PRIORITY_SOURCES:
        score, reason = values[source]
        weight = _WEIGHTS[source] / total if complete and score is not None else 0.0
        components.append(
            SourcePriorityComponent(
                source=source,
                status="completed" if score is not None else "unavailable",
                reason=reason,
                evidence=refs.get(_source_kind(source)),
                observation=observations[source],
                raw_score=score,
                configured_weight=_WEIGHTS[source],
                effective_weight=weight,
                contribution=score * weight if complete and score is not None else None,
            )
        )
    typed_components = tuple(components)
    guardrails = _guardrails(typed_components)
    aggregate = (
        min(
            1.0,
            max(
                (
                    sum(
                        row.contribution for row in typed_components if row.contribution is not None
                    ),
                    *(row.floor for row in guardrails),
                )
            ),
        )
        if complete
        else None
    )
    return SourcePriorityComposition(
        report_id=report.report_id,
        report_sha256=report.review_sha256,
        report_version=report.version,
        patch_id=report.patch_id,
        draft_sha256=report.draft_sha256,
        before=report.before,
        after=report.after,
        before_analysis_id=report.before_analysis_id,
        before_analysis_sha256=report.before_analysis_sha256,
        selected_evidence=selected,
        coverage=draft.diff.coverage,
        candidate_parser_confidence=draft.diff.after.parser_confidence,
        components=typed_components,
        availability_mask=mask,
        status="completed" if complete else "unavailable",
        score=aggregate,
        band=_band(aggregate) if aggregate is not None else None,
        applicable_guardrails=guardrails,
        applied_guardrails=guardrails if complete else (),
    )


def validate_source_priority(
    composition: SourcePriorityComposition,
    draft: PatchDraft,
    report: SourceEvidenceReportRecord,
    deterministic: SourceDeterministicRecheck,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
) -> None:
    """A consistent projection alone cannot replace the exact retained child observations."""
    actual = SourcePriorityComposition.model_validate(composition.model_dump(warnings=False))
    expected = compose_source_priority(
        draft, report, deterministic, forest=forest, neural=neural, network=network
    )
    if actual != expected:
        raise ValueError("priority differs from the exact selected evidence composition")
