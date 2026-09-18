"""Versioned policy catalog kept separate from execution code."""

from app.domain import Severity
from app.policies.models import ManagementField, PolicyPlatform, PolicyRule

POLICY_CATALOG_VERSION = "policy-rules-0.1.0"

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

POLICY_RULES = MANAGEMENT_RULES
