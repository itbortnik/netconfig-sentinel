"""Transparent weighted risk fusion with non-negotiable formal guardrails."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from uuid import UUID, uuid5

from app.detection.fusion.models import (
    RiskAssessment,
    RiskComponent,
    RiskLevel,
    RiskSource,
    SignalStatus,
    VerificationImpact,
)
from app.domain import Finding, Severity

RISK_FUSION_NAMESPACE = UUID("6787f07b-57ed-4d10-822a-e174d4395ac6")

RISK_WEIGHTS = {
    RiskSource.POLICY: 0.35,
    RiskSource.PEER_GROUP: 0.15,
    RiskSource.STATISTICAL: 0.10,
    RiskSource.TRANSFORMER: 0.10,
    RiskSource.VERIFICATION: 0.30,
}

_DETECTOR_SOURCES = {
    "policy_engine": RiskSource.POLICY,
    "peer_baseline": RiskSource.PEER_GROUP,
    "isolation_forest": RiskSource.STATISTICAL,
    "config_transformer": RiskSource.TRANSFORMER,
}

_SEVERITY_SCORES = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.50,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.00,
}

_VERIFICATION_SCORES = {
    VerificationImpact.NO_ADVERSE_IMPACT: 0.0,
    VerificationImpact.POLICY_REGRESSION: 0.75,
    VerificationImpact.LOSS_OF_REACHABILITY: 1.0,
}


def fuse_risk(
    findings: Sequence[Finding],
    *,
    device_id: UUID,
    completed_detectors: Iterable[RiskSource],
    verification_impact: VerificationImpact = VerificationImpact.NOT_RUN,
) -> RiskAssessment:
    """Fuse completed detector results and an optional verification outcome."""

    completed = set(completed_detectors)
    if RiskSource.VERIFICATION in completed:
        raise ValueError("verification completion is represented by verification_impact")
    if len({finding.finding_id for finding in findings}) != len(findings):
        raise ValueError("finding identifiers must be unique")

    findings_by_source: dict[RiskSource, list[Finding]] = {
        source: [] for source in RiskSource if source is not RiskSource.VERIFICATION
    }
    for finding in findings:
        source = _DETECTOR_SOURCES.get(finding.detector)
        if source is None:
            raise ValueError(f"unsupported detector for risk fusion: {finding.detector}")
        if source not in completed:
            raise ValueError(
                f"finding source {source.value} is not marked as completed"
            )
        if finding.device_id != device_id:
            raise ValueError("all findings must belong to the assessed device")
        findings_by_source[source].append(finding)

    verification_completed = verification_impact is not VerificationImpact.NOT_RUN
    available_sources = set(completed)
    if verification_completed:
        available_sources.add(RiskSource.VERIFICATION)
    if not available_sources:
        raise ValueError("at least one completed risk source is required")

    available_weight = sum(RISK_WEIGHTS[source] for source in available_sources)
    components: list[RiskComponent] = []
    for source in RiskSource:
        if source not in available_sources:
            components.append(
                RiskComponent(
                    source=source,
                    status=SignalStatus.UNAVAILABLE,
                    configured_weight=RISK_WEIGHTS[source],
                    effective_weight=0.0,
                )
            )
            continue
        source_findings = findings_by_source.get(source, [])
        raw_score = (
            _VERIFICATION_SCORES[verification_impact]
            if source is RiskSource.VERIFICATION
            else _detector_score(source_findings)
        )
        components.append(
            RiskComponent(
                source=source,
                status=SignalStatus.COMPLETED,
                raw_score=raw_score,
                configured_weight=RISK_WEIGHTS[source],
                effective_weight=RISK_WEIGHTS[source] / available_weight,
                finding_ids=tuple(
                    sorted(
                        (finding.finding_id for finding in source_findings),
                        key=str,
                    )
                ),
            )
        )

    weighted_score = sum(
        (component.raw_score or 0.0) * component.effective_weight
        for component in components
    )
    guardrails: list[str] = []
    if any(
        finding.detector == "policy_engine"
        and finding.severity is Severity.CRITICAL
        for finding in findings
    ):
        weighted_score = max(weighted_score, 0.90)
        guardrails.append(
            "A critical deterministic policy finding sets a minimum risk score of 0.90."
        )
    if verification_impact is VerificationImpact.LOSS_OF_REACHABILITY:
        weighted_score = max(weighted_score, 0.95)
        guardrails.append(
            "Verified loss of reachability sets a minimum risk score of 0.95."
        )

    limitations = tuple(
        f"{source.value} signal was not available and its weight was redistributed."
        for source in RiskSource
        if source not in available_sources
    )
    score = min(1.0, weighted_score)
    return RiskAssessment(
        assessment_id=_assessment_id(
            device_id,
            findings,
            completed,
            verification_impact,
        ),
        device_id=device_id,
        score=score,
        level=_risk_level(score),
        components=tuple(components),
        guardrails=tuple(guardrails),
        limitations=limitations,
    )


def _detector_score(findings: Sequence[Finding]) -> float:
    if not findings:
        return 0.0
    return max(
        max(_SEVERITY_SCORES[finding.severity], finding.anomaly_score)
        * finding.confidence
        for finding in findings
    )


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.80:
        return RiskLevel.CRITICAL
    if score >= 0.50:
        return RiskLevel.HIGH
    if score >= 0.25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _assessment_id(
    device_id: UUID,
    findings: Sequence[Finding],
    completed: set[RiskSource],
    verification_impact: VerificationImpact,
) -> UUID:
    finding_key = ",".join(sorted(str(finding.finding_id) for finding in findings))
    completed_key = ",".join(sorted(source.value for source in completed))
    return uuid5(
        RISK_FUSION_NAMESPACE,
        f"{device_id}:{finding_key}:{completed_key}:{verification_impact.value}",
    )
