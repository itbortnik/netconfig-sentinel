"""Versioned policy catalog kept separate from execution code."""

from app.domain import Severity
from app.policies.models import (
    AclField,
    Layer2Field,
    ManagementField,
    PolicyOperator,
    PolicyPlatform,
    PolicyRule,
    RoutingField,
)

POLICY_CATALOG_VERSION = "policy-rules-0.5.0"

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

ACCESS_CONTROL_RULES = (
    PolicyRule(
        rule_id="acl.empty",
        title="ACL has no effective rules",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=AclField.EMPTY,
        operator=PolicyOperator.MATCHES,
        expected_value="At least one explicit ACL rule",
        evidence_message="The ACL contains no rule with a supported action.",
        remediation="Add the intended restrictive rules or remove the unused ACL.",
        references=("docs/policies/access-control.md#acls-must-not-be-empty",),
    ),
    PolicyRule(
        rule_id="acl.unrestricted_permit",
        title="ACL contains an unrestricted permit",
        severity=Severity.CRITICAL,
        platforms=SUPPORTED_PLATFORMS,
        field=AclField.UNRESTRICTED_PERMIT,
        operator=PolicyOperator.MATCHES,
        expected_value="Permit rules constrained by source, destination, or port",
        evidence_message="The rule permits a protocol without address or port constraints.",
        remediation=(
            "Replace the rule with least-privilege source, destination, and service matches."
        ),
        references=("docs/policies/access-control.md#unrestricted-permits-are-forbidden",),
    ),
    PolicyRule(
        rule_id="acl.telnet_permitted",
        title="ACL explicitly permits Telnet",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=AclField.TELNET_PERMITTED,
        operator=PolicyOperator.MATCHES,
        expected_value="No permit rule matching TCP port 23",
        evidence_message="The rule explicitly permits Telnet traffic.",
        remediation="Remove the Telnet permit and allow SSH from approved sources instead.",
        references=("docs/policies/access-control.md#telnet-must-not-be-permitted",),
    ),
    PolicyRule(
        rule_id="acl.management_access_from_any",
        title="ACL permits management access from any source",
        severity=Severity.CRITICAL,
        platforms=SUPPORTED_PLATFORMS,
        field=AclField.MANAGEMENT_ACCESS_FROM_ANY,
        operator=PolicyOperator.MATCHES,
        expected_value="SSH and SNMP permits restricted to approved source networks",
        evidence_message="The rule permits SSH or SNMP from an unrestricted source.",
        remediation="Restrict management services to approved management networks.",
        references=("docs/policies/access-control.md#management-sources-must-be-restricted",),
    ),
)

ROUTING_RULES = (
    PolicyRule(
        rule_id="bgp.router_id_missing",
        title="BGP router ID is not explicitly configured",
        severity=Severity.MEDIUM,
        platforms=SUPPORTED_PLATFORMS,
        field=RoutingField.BGP_ROUTER_ID_MISSING,
        operator=PolicyOperator.MATCHES,
        expected_value="An explicit stable IPv4 BGP router ID",
        evidence_message="The BGP process has no explicit router ID in supported syntax.",
        remediation="Configure a stable BGP router ID according to the addressing plan.",
        references=("docs/policies/routing.md#bgp-router-id-must-be-explicit",),
    ),
    PolicyRule(
        rule_id="bgp.neighbor_is_local_address",
        title="BGP neighbor uses a local interface address",
        severity=Severity.CRITICAL,
        platforms=SUPPORTED_PLATFORMS,
        field=RoutingField.BGP_NEIGHBOR_IS_LOCAL,
        operator=PolicyOperator.MATCHES,
        expected_value="A remote peer address not assigned to this device",
        evidence_message="The BGP neighbor address is also assigned to a local interface.",
        remediation="Correct the neighbor address and verify the intended peer endpoint.",
        references=("docs/policies/routing.md#bgp-neighbors-must-be-remote",),
    ),
    PolicyRule(
        rule_id="ospf.router_id_missing",
        title="OSPF router ID is not explicitly configured",
        severity=Severity.MEDIUM,
        platforms=SUPPORTED_PLATFORMS,
        field=RoutingField.OSPF_ROUTER_ID_MISSING,
        operator=PolicyOperator.MATCHES,
        expected_value="An explicit stable IPv4 OSPF router ID",
        evidence_message="The OSPF process has no explicit router ID in supported syntax.",
        remediation="Configure a stable OSPF router ID according to the addressing plan.",
        references=("docs/policies/routing.md#ospf-router-id-must-be-explicit",),
    ),
    PolicyRule(
        rule_id="routing.default_route_discarded",
        title="Default static route is discarded",
        severity=Severity.CRITICAL,
        platforms=SUPPORTED_PLATFORMS,
        field=RoutingField.DEFAULT_ROUTE_DISCARDED,
        operator=PolicyOperator.MATCHES,
        expected_value="A forwarding next hop for default routes",
        evidence_message="The IPv4 or IPv6 default route points to a discard action.",
        remediation="Remove the discard default or replace it with the intended forwarding path.",
        references=("docs/policies/routing.md#default-routes-must-not-be-discarded",),
    ),
)

LAYER2_RULES = (
    PolicyRule(
        rule_id="interface.access_vlan_missing",
        title="Access interface has no explicit VLAN",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=Layer2Field.ACCESS_VLAN_MISSING,
        operator=PolicyOperator.MATCHES,
        expected_value="An explicit access VLAN on every access interface",
        evidence_message="The interface is in access mode without an explicit access VLAN.",
        remediation="Assign the intended access VLAN explicitly.",
        references=("docs/policies/layer2.md#access-vlans-must-be-explicit",),
    ),
    PolicyRule(
        rule_id="interface.trunk_vlans_unrestricted",
        title="Trunk interface permits an unrestricted VLAN set",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=Layer2Field.TRUNK_VLANS_UNRESTRICTED,
        operator=PolicyOperator.MATCHES,
        expected_value="An explicit least-privilege allowed VLAN set",
        evidence_message="The trunk has no explicit VLAN restriction or permits all VLANs.",
        remediation="Configure only the VLANs required on this trunk.",
        references=("docs/policies/layer2.md#trunk-vlans-must-be-restricted",),
    ),
    PolicyRule(
        rule_id="interface.switchport_mode_conflict",
        title="Interface contains conflicting switchport parameters",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=Layer2Field.SWITCHPORT_MODE_CONFLICT,
        operator=PolicyOperator.MATCHES,
        expected_value="Switchport parameters consistent with the configured mode",
        evidence_message="The interface mixes access and trunk-only parameters.",
        remediation="Remove stale parameters and configure one intended switchport mode.",
        references=("docs/policies/layer2.md#switchport-mode-must-be-consistent",),
    ),
)

POLICY_RULES = (
    MANAGEMENT_RULES
    + OBSERVABILITY_RULES
    + ACCESS_CONTROL_RULES
    + ROUTING_RULES
    + LAYER2_RULES
)
