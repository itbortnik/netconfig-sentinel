"""Versioned policy catalog kept separate from execution code."""

from app.domain import Severity
from app.policies.models import (
    ManagementField,
    PolicyOperator,
    PolicyPlatform,
    PolicyRule,
)

POLICY_CATALOG_VERSION = "policy-rules-0.2.0"

SUPPORTED_PLATFORMS = (
    PolicyPlatform.CISCO_IOS,
    PolicyPlatform.JUNIPER_JUNOS,
)

MANAGEMENT_RULES = (
    PolicyRule(
        rule_id="management.telnet_enabled",
        title="Telnet is enabled on the management plane",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.TELNET_ENABLED,
        violation_value=True,
        expected_value=False,
        evidence_message="Telnet permits unencrypted remote management sessions.",
        remediation="Disable Telnet and permit SSH for remote administrative access.",
        references=("docs/policies/management-plane.md#telnet-must-be-disabled",),
    ),
    PolicyRule(
        rule_id="management.ssh_disabled",
        title="SSH is not enabled on the management plane",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.SSH_ENABLED,
        violation_value=False,
        expected_value=True,
        evidence_message="No supported SSH enablement statement was found.",
        remediation="Enable SSH and restrict it to approved management sources.",
        references=("docs/policies/management-plane.md#ssh-must-be-enabled",),
    ),
    PolicyRule(
        rule_id="management.aaa_disabled",
        title="Centralized AAA is not enabled",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.AAA_ENABLED,
        violation_value=False,
        expected_value=True,
        evidence_message="No supported centralized AAA enablement statement was found.",
        remediation="Enable centralized AAA with an explicitly tested local fallback.",
        references=("docs/policies/management-plane.md#centralized-aaa-must-be-enabled",),
    ),
)

OBSERVABILITY_RULES = (
    PolicyRule(
        rule_id="management.snmp_legacy_enabled",
        title="Legacy SNMP is enabled",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.SNMP_VERSIONS,
        operator=PolicyOperator.CONTAINS_ANY,
        violation_value=("v1", "v2c"),
        expected_value="SNMPv3 only, or SNMP disabled",
        evidence_message="SNMPv1 or SNMPv2c is configured without modern protection.",
        remediation="Migrate monitoring to SNMPv3 and remove legacy communities.",
        references=("docs/policies/observability.md#legacy-snmp-must-be-disabled",),
    ),
    PolicyRule(
        rule_id="management.snmp_not_configured",
        title="SNMP monitoring is not configured",
        severity=Severity.MEDIUM,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.SNMP_VERSIONS,
        operator=PolicyOperator.IS_EMPTY,
        expected_value="At least one approved SNMP version",
        evidence_message="No supported SNMP configuration was found.",
        remediation="Configure SNMPv3 monitoring or document an approved alternative.",
        references=("docs/policies/observability.md#monitoring-must-be-configured",),
    ),
    PolicyRule(
        rule_id="management.ntp_not_configured",
        title="NTP is not configured",
        severity=Severity.MEDIUM,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.NTP_SERVERS,
        operator=PolicyOperator.IS_EMPTY,
        expected_value="At least one approved NTP server",
        evidence_message="No supported NTP server statement was found.",
        remediation="Configure approved redundant NTP servers.",
        references=("docs/policies/observability.md#time-synchronization-is-required",),
    ),
    PolicyRule(
        rule_id="management.syslog_not_configured",
        title="Remote Syslog is not configured",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.SYSLOG_SERVERS,
        operator=PolicyOperator.IS_EMPTY,
        expected_value="At least one approved remote Syslog server",
        evidence_message="No supported remote Syslog destination was found.",
        remediation="Send security and operational events to approved remote collectors.",
        references=("docs/policies/observability.md#remote-audit-logging-is-required",),
    ),
)

POLICY_RULES = MANAGEMENT_RULES + OBSERVABILITY_RULES
