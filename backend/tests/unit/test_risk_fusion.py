"""Tests for transparent weighted risk fusion and safety guardrails."""

from uuid import UUID, uuid4

import pytest
from app.detection import (
    RiskLevel,
    RiskSource,
    SignalStatus,
    VerificationImpact,
    fuse_risk,
)
from app.domain import Finding, Severity

DEVICE_ID = UUID("bf902d6f-4c5c-47c4-862f-65e47e874fa1")


def _finding(
    detector: str,
    severity: Severity,
    *,
    confidence: float = 1.0,
    anomaly_score: float = 0.0,
    device_id: UUID = DEVICE_ID,
) -> Finding:
    return Finding(
        finding_id=uuid4(),
        device_id=device_id,
        detector=detector,
        category=f"test.{detector}",
        title="Test finding",
        severity=severity,
        confidence=confidence,
        anomaly_score=anomaly_score,
        model_version="test-1.0",
    )


def test_weighted_formula_uses_only_completed_sources() -> None:
    findings = [
        _finding("policy_engine", Severity.HIGH),
        _finding(
            "peer_baseline",
            Severity.HIGH,
            confidence=0.8,
            anomaly_score=0.9,
        ),
        _finding(
            "isolation_forest",
            Severity.MEDIUM,
            confidence=0.5,
            anomaly_score=0.8,
        ),
    ]

    assessment = fuse_risk(
        findings,
        device_id=DEVICE_ID,
        completed_detectors=(
            RiskSource.POLICY,
            RiskSource.PEER_GROUP,
            RiskSource.STATISTICAL,
        ),
        verification_impact=VerificationImpact.NO_ADVERSE_IMPACT,
    )

    expected = (0.35 * 0.75 + 0.15 * 0.72 + 0.10 * 0.40) / 0.90
    assert assessment.score == pytest.approx(expected)
    assert assessment.level is RiskLevel.MEDIUM
    transformer = next(
        item
        for item in assessment.components
        if item.source is RiskSource.TRANSFORMER
    )
    assert transformer.status is SignalStatus.UNAVAILABLE
    assert transformer.effective_weight == 0.0
    assert assessment.limitations == (
        "transformer signal was not available and its weight was redistributed.",
    )


def test_completed_detector_without_findings_contributes_zero() -> None:
    assessment = fuse_risk(
        [],
        device_id=DEVICE_ID,
        completed_detectors=(RiskSource.POLICY,),
    )

    policy = next(
        item for item in assessment.components if item.source is RiskSource.POLICY
    )
    assert policy.status is SignalStatus.COMPLETED
    assert policy.raw_score == 0.0
    assert policy.effective_weight == 1.0
    assert assessment.score == 0.0
    assert assessment.level is RiskLevel.LOW


def test_critical_policy_guardrail_prevents_low_risk() -> None:
    critical = _finding(
        "policy_engine",
        Severity.CRITICAL,
        confidence=0.1,
    )

    assessment = fuse_risk(
        [critical],
        device_id=DEVICE_ID,
        completed_detectors=(RiskSource.POLICY,),
    )

    assert assessment.score == 0.9
    assert assessment.level is RiskLevel.CRITICAL
    assert assessment.guardrails == (
        "A critical deterministic policy finding sets a minimum risk score of 0.90.",
    )


def test_verified_reachability_loss_forces_critical_risk() -> None:
    assessment = fuse_risk(
        [],
        device_id=DEVICE_ID,
        completed_detectors=(RiskSource.POLICY,),
        verification_impact=VerificationImpact.LOSS_OF_REACHABILITY,
    )

    assert assessment.score == 0.95
    assert assessment.level is RiskLevel.CRITICAL
    assert assessment.guardrails == (
        "Verified loss of reachability sets a minimum risk score of 0.95.",
    )


def test_assessment_id_is_independent_of_finding_order() -> None:
    policy = _finding("policy_engine", Severity.HIGH)
    statistical = _finding(
        "isolation_forest", Severity.MEDIUM, anomaly_score=0.8
    )
    completed = (RiskSource.POLICY, RiskSource.STATISTICAL)

    first = fuse_risk(
        [policy, statistical],
        device_id=DEVICE_ID,
        completed_detectors=completed,
    )
    reordered = fuse_risk(
        [statistical, policy],
        device_id=DEVICE_ID,
        completed_detectors=reversed(completed),
    )

    assert first.assessment_id == reordered.assessment_id
    assert first.score == reordered.score


@pytest.mark.parametrize(
    ("findings", "completed", "message"),
    (
        (
            [_finding("unknown_detector", Severity.MEDIUM)],
            (RiskSource.POLICY,),
            "unsupported detector",
        ),
        (
            [_finding("policy_engine", Severity.MEDIUM)],
            (RiskSource.STATISTICAL,),
            "not marked as completed",
        ),
        (
            [
                _finding(
                    "policy_engine",
                    Severity.MEDIUM,
                    device_id=UUID("50805cd7-513e-4867-a9a5-94be5610ee58"),
                )
            ],
            (RiskSource.POLICY,),
            "assessed device",
        ),
    ),
)
def test_invalid_finding_inputs_are_rejected(
    findings: list[Finding],
    completed: tuple[RiskSource, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        fuse_risk(
            findings,
            device_id=DEVICE_ID,
            completed_detectors=completed,
        )


def test_fusion_requires_at_least_one_available_source() -> None:
    with pytest.raises(ValueError, match="at least one completed"):
        fuse_risk([], device_id=DEVICE_ID, completed_detectors=())
