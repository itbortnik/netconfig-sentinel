"""Deterministic execution of declarative configuration policies."""

from __future__ import annotations

from uuid import UUID, uuid5

from app.domain import CanonicalConfig, Evidence, Finding, SourceLocation, Vendor
from app.policies import (
    POLICY_CATALOG_VERSION,
    POLICY_RULES,
    ManagementField,
    PolicyPlatform,
    PolicyRule,
)

POLICY_FINDING_NAMESPACE = UUID("79c10c39-c6bd-43f5-9d24-37d7fa2c9e69")


def evaluate_policies(
    config: CanonicalConfig,
    *,
    device_id: UUID,
    rules: tuple[PolicyRule, ...] = POLICY_RULES,
) -> list[Finding]:
    """Return policy violations in catalog order for a canonical configuration."""

    platform = _platform_for(config)
    findings: list[Finding] = []
    for rule in rules:
        if platform not in rule.platforms:
            continue
        actual = _management_value(config, rule.field)
        if actual != rule.violation_value:
            continue
        location = _management_location(config, rule.field)
        affected_lines = location.source_lines if location is not None else []
        limitations = []
        if location is None:
            limitations.append(
                "The violation is inferred from the absence of supported enablement syntax."
            )
        findings.append(
            Finding(
                finding_id=_finding_id(device_id, rule.rule_id, affected_lines),
                device_id=device_id,
                detector="policy_engine",
                category=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=(
                    location.parser_confidence
                    if location is not None
                    else config.parser_confidence
                ),
                anomaly_score=0.0,
                affected_lines=affected_lines,
                evidence=[
                    Evidence(
                        kind="policy_violation",
                        message=rule.evidence_message,
                        source_location=location,
                    )
                ],
                observed={rule.field.value: actual},
                expected={rule.field.value: rule.expected_value},
                remediation=rule.remediation,
                references=list(rule.references),
                limitations=limitations,
                model_version=POLICY_CATALOG_VERSION,
            )
        )
    return findings


def _platform_for(config: CanonicalConfig) -> PolicyPlatform:
    if config.device.vendor is Vendor.CISCO and config.device.platform == "ios":
        return PolicyPlatform.CISCO_IOS
    if config.device.vendor is Vendor.JUNIPER and config.device.platform == "junos":
        return PolicyPlatform.JUNIPER_JUNOS
    raise ValueError(
        f"unsupported policy platform: {config.device.vendor.value}/{config.device.platform}"
    )


def _management_value(config: CanonicalConfig, field: ManagementField) -> bool:
    if field is ManagementField.SSH_ENABLED:
        return config.management.ssh_enabled
    if field is ManagementField.TELNET_ENABLED:
        return config.management.telnet_enabled
    if field is ManagementField.AAA_ENABLED:
        return config.management.aaa_enabled
    raise ValueError(f"unsupported management field: {field}")


def _management_location(
    config: CanonicalConfig, field: ManagementField
) -> SourceLocation | None:
    return config.management.provenance.get(field.value.removeprefix("management."))


def _finding_id(device_id: UUID, rule_id: str, affected_lines: list[int]) -> UUID:
    line_key = ",".join(str(line) for line in affected_lines)
    return uuid5(POLICY_FINDING_NAMESPACE, f"{device_id}:{rule_id}:{line_key}")
