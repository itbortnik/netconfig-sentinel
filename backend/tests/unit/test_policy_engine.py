"""Tests for deterministic declarative policy evaluation."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from app.detection import evaluate_policies
from app.domain import Severity
from app.parsers import parse_configuration
from app.policies import MANAGEMENT_RULES

DEVICE_ID = UUID("619e8467-a870-464d-890e-4b5209058c8a")
COLLECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("rule_id", "violating_text", "compliant_text", "affected_lines"),
    (
        (
            "management.telnet_enabled",
            "hostname edge\nline vty 0 4\n transport input telnet\n",
            "hostname edge\nline vty 0 4\n transport input ssh\n",
            [3],
        ),
        (
            "management.ssh_disabled",
            "hostname edge\n",
            "hostname edge\nip ssh version 2\n",
            [],
        ),
        (
            "management.aaa_disabled",
            "hostname edge\nno aaa new-model\n",
            "hostname edge\naaa new-model\n",
            [2],
        ),
    ),
)
def test_each_management_rule_has_positive_and_negative_case(
    rule_id: str,
    violating_text: str,
    compliant_text: str,
    affected_lines: list[int],
) -> None:
    rule = next(rule for rule in MANAGEMENT_RULES if rule.rule_id == rule_id)
    violating = parse_configuration(
        violating_text,
        filename="device.cfg",
        collected_at=COLLECTED_AT,
    )
    compliant = parse_configuration(
        compliant_text,
        filename="device.cfg",
        collected_at=COLLECTED_AT,
    )

    positive = evaluate_policies(violating, device_id=DEVICE_ID, rules=(rule,))
    negative = evaluate_policies(compliant, device_id=DEVICE_ID, rules=(rule,))

    assert len(positive) == 1
    assert negative == []
    assert positive[0].category == rule_id
    assert positive[0].severity is Severity.HIGH
    assert positive[0].affected_lines == affected_lines
    assert positive[0].remediation == rule.remediation
    assert positive[0].references == list(rule.references)


def test_finding_ids_are_stable_and_change_with_evidence_location() -> None:
    first = parse_configuration(
        "hostname edge\nline vty 0 4\n transport input telnet\n",
        filename="device.cfg",
        collected_at=COLLECTED_AT,
    )
    shifted = parse_configuration(
        "! comment\nhostname edge\nline vty 0 4\n transport input telnet\n",
        filename="device.cfg",
        collected_at=COLLECTED_AT,
    )
    rule = (MANAGEMENT_RULES[0],)

    first_run = evaluate_policies(first, device_id=DEVICE_ID, rules=rule)
    repeated_run = evaluate_policies(first, device_id=DEVICE_ID, rules=rule)
    shifted_run = evaluate_policies(shifted, device_id=DEVICE_ID, rules=rule)

    assert first_run[0].finding_id == repeated_run[0].finding_id
    assert first_run[0].finding_id != shifted_run[0].finding_id


def test_absence_based_finding_declares_its_limitation() -> None:
    config = parse_configuration(
        "hostname edge\n",
        filename="device.cfg",
        collected_at=COLLECTED_AT,
    )
    ssh_rule = (MANAGEMENT_RULES[1],)

    finding = evaluate_policies(config, device_id=DEVICE_ID, rules=ssh_rule)[0]

    assert finding.affected_lines == []
    assert finding.evidence[0].source_location is None
    assert finding.limitations == [
        "The violation is inferred from the absence of supported enablement syntax."
    ]
