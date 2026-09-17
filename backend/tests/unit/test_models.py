"""Validation tests for public domain contracts."""

from uuid import uuid4

import pytest
from app.domain import Finding, Severity, SourceLocation
from app.domain.models import ConfigSource
from pydantic import ValidationError

VALID_HASH = "0" * 64


def test_source_location_requires_ordered_unique_positive_lines() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(
            source_lines=[2, 1, 2],
            raw_text_hash=VALID_HASH,
            parser_confidence=1.0,
        )


def test_source_rejects_paths(collected_at: object) -> None:
    with pytest.raises(ValidationError):
        ConfigSource(
            filename="../router.cfg",
            sha256=VALID_HASH,
            collected_at=collected_at,
        )


def test_finding_keeps_severity_confidence_and_anomaly_score_separate() -> None:
    finding = Finding(
        finding_id=uuid4(),
        device_id=uuid4(),
        detector="policy_engine",
        category="management.telnet_enabled",
        title="Telnet is enabled",
        severity=Severity.HIGH,
        confidence=1.0,
        anomaly_score=0.0,
        affected_lines=[6],
        model_version="rules-0.1.0",
    )

    assert finding.severity is Severity.HIGH
    assert finding.confidence == 1.0
    assert finding.anomaly_score == 0.0
