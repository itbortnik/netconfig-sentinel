"""Versioned policy catalog kept separate from execution code."""

from types import MappingProxyType

from app.domain import Severity
from app.policies.models import (
    AccountField,
    AclField,
    DeviceField,
    Layer2Field,
    ManagementField,
    PolicyOperator,
    PolicyPlatform,
    PolicyRule,
    RoutingField,
)

POLICY_CATALOG_VERSION = "policy-rules-0.7.0"

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
    PolicyRule(
        rule_id="management.hostname_missing",
        title="Device hostname is not configured",
        severity=Severity.MEDIUM,
        platforms=SUPPORTED_PLATFORMS,
        field=DeviceField.HOSTNAME_MISSING,
        operator=PolicyOperator.MATCHES,
        expected_value="An explicit unique hostname",
        evidence_message="No supported hostname statement was found.",
        remediation="Configure a unique hostname that follows the inventory naming standard.",
        references=("docs/policies/management-plane.md#hostname-must-be-explicit",),
    ),
    PolicyRule(
        rule_id="management.ssh_version_1",
        title="SSHv1 is explicitly configured",
        severity=Severity.HIGH,
        platforms=SUPPORTED_PLATFORMS,
        field=ManagementField.SSH_VERSION,
        violation_value="1",
        expected_value="2",
        evidence_message="The management service explicitly selects SSH protocol version 1.",
        remediation="Require SSH protocol version 2 and remove SSHv1 compatibility.",
        references=("docs/policies/management-plane.md#ssh-version-1-must-be-disabled",),
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

LEGACY_POLICY_RULES = (
    MANAGEMENT_RULES + OBSERVABILITY_RULES + ACCESS_CONTROL_RULES + ROUTING_RULES + LAYER2_RULES
)


def _derived_rule(
    rule_id: str,
    title: str,
    severity: Severity,
    field: AccountField | RoutingField | Layer2Field,
    expected: str,
    evidence: str,
    remediation: str,
    reference: str,
    platforms: tuple[PolicyPlatform, ...] = SUPPORTED_PLATFORMS,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        title=title,
        severity=severity,
        platforms=platforms,
        field=field,
        operator=PolicyOperator.MATCHES,
        expected_value=expected,
        evidence_message=evidence,
        remediation=remediation,
        references=(reference,),
    )


ACCOUNT_RULES = (
    _derived_rule(
        "account.passwordless",
        "Local account explicitly permits no password",
        Severity.CRITICAL,
        AccountField.PASSWORDLESS,
        "No explicit passwordless local accounts",
        "A supported local account statement explicitly selects nopassword.",
        "Require an approved credential and review intended fallback access before changing it.",
        "docs/policies/management-plane.md#local-accounts-must-not-be-passwordless",
        (PolicyPlatform.CISCO_IOS,),
    ),
    _derived_rule(
        "account.cleartext_credential",
        "Local credential is explicitly stored as type 0",
        Severity.HIGH,
        AccountField.CLEARTEXT,
        "No explicitly stored type-0 credentials",
        "The account explicitly declares unencrypted credential storage type 0.",
        "Replace the credential with an approved non-reversible format and protect source files.",
        "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
        (PolicyPlatform.CISCO_IOS,),
    ),
    _derived_rule(
        "account.reversible_password",
        "Local password uses reversible type 7",
        Severity.HIGH,
        AccountField.REVERSIBLE,
        "No reversible type-7 local passwords",
        "The supported local password statement explicitly declares storage type 7.",
        "Migrate to an approved non-reversible secret after testing administrative fallback.",
        "docs/policies/management-plane.md#local-passwords-must-not-be-reversible",
        (PolicyPlatform.CISCO_IOS,),
    ),
    _derived_rule(
        "account.legacy_secret",
        "Local secret uses legacy type 4 or 5",
        Severity.MEDIUM,
        AccountField.LEGACY_SECRET,
        "An approved modern secret format",
        "The local secret explicitly declares legacy storage type 4 or 5.",
        "Review release compatibility and migrate to an approved modern secret format.",
        "docs/policies/management-plane.md#local-secrets-must-not-use-legacy-formats",
        (PolicyPlatform.CISCO_IOS,),
    ),
    _derived_rule(
        "account.duplicate_uid",
        "Different local accounts share an explicit UID",
        Severity.HIGH,
        AccountField.DUPLICATE_UID,
        "Unique explicitly assigned account UIDs",
        "Two or more supported account entries declare the same numeric UID.",
        "Review account identity mappings and assign unique UIDs through the approved process.",
        "docs/policies/management-plane.md#local-account-uids-must-be-unique",
        (PolicyPlatform.JUNIPER_JUNOS,),
    ),
)

ADDITIONAL_ROUTING_RULES = (
    _derived_rule(
        "routing.static_next_hop_is_local",
        "Static route points to a local interface address",
        Severity.HIGH,
        RoutingField.STATIC_NEXT_HOP_IS_LOCAL,
        "A remote forwarding next hop",
        "An explicit static-route next hop equals an address configured on this device.",
        "Review the route target, VRF scope and intended neighbor before changing the route.",
        "docs/policies/routing.md#static-next-hops-must-not-be-local-addresses",
    ),
    _derived_rule(
        "routing.static_next_hop_non_unicast",
        "Static next hop is not a unicast target",
        Severity.HIGH,
        RoutingField.STATIC_NEXT_HOP_NON_UNICAST,
        "A unicast forwarding next hop",
        "An explicit static next hop is multicast, unspecified or limited broadcast.",
        "Choose the intended unicast neighbor or an explicit supported discard action.",
        "docs/policies/routing.md#static-next-hops-must-be-unicast",
    ),
)

ADDITIONAL_INTERFACE_RULES = (
    _derived_rule(
        "interface.vlan_reference_undefined",
        "Interface references an undefined local VLAN",
        Severity.MEDIUM,
        Layer2Field.VLAN_REFERENCE_UNDEFINED,
        "Explicit local definitions for referenced VLANs",
        "A supported explicit VLAN reference has no matching local VLAN definition.",
        "Confirm VLAN provisioning and define the intended VLAN or remove the stale reference.",
        "docs/policies/layer2.md#referenced-vlans-must-have-local-definitions",
    ),
    _derived_rule(
        "interface.native_vlan_excluded",
        "Native VLAN is excluded from an explicit trunk set",
        Severity.MEDIUM,
        Layer2Field.NATIVE_VLAN_EXCLUDED,
        "Native VLAN included in the intended Cisco trunk set",
        "The explicit Cisco trunk allowed set excludes its explicitly configured native VLAN.",
        "Review intentional native-VLAN filtering and align the native VLAN and allowed set.",
        "docs/policies/layer2.md#native-vlan-filtering-must-be-reviewed",
        (PolicyPlatform.CISCO_IOS,),
    ),
    _derived_rule(
        "interface.duplicate_address",
        "Different interfaces declare the same host address",
        Severity.HIGH,
        Layer2Field.DUPLICATE_ADDRESS,
        "Unique interface host addresses within the reviewed scope",
        "The same IP host address appears on two or more different supported interfaces.",
        "Review anycast, VRFs and interface ownership before resolving duplicate addresses.",
        "docs/policies/layer2.md#duplicate-interface-addresses-must-be-reviewed",
    ),
)

POLICY_RULES = (
    LEGACY_POLICY_RULES + ACCOUNT_RULES + ADDITIONAL_ROUTING_RULES + ADDITIONAL_INTERFACE_RULES
)
POLICY_CATALOGS = MappingProxyType(
    {
        "policy-rules-0.6.0": LEGACY_POLICY_RULES,
        POLICY_CATALOG_VERSION: POLICY_RULES,
    }
)
