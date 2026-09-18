"""Tests for deterministic declarative policy evaluation."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from app.detection import evaluate_policies
from app.domain import Severity
from app.parsers import parse_configuration
from app.policies import (
    ACCESS_CONTROL_RULES,
    LAYER2_RULES,
    MANAGEMENT_RULES,
    OBSERVABILITY_RULES,
    POLICY_RULES,
    ROUTING_RULES,
)

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
        "The violation is inferred from the absence of supported configuration syntax."
    ]


@pytest.mark.parametrize(
    ("rule_id", "violating_text", "compliant_text", "affected_lines"),
    (
        (
            "management.snmp_legacy_enabled",
            "hostname edge\nsnmp-server community public ro\n",
            "hostname edge\nsnmp-server group SECURE v3 priv\n",
            [2],
        ),
        (
            "management.snmp_not_configured",
            "hostname edge\n",
            "hostname edge\nsnmp-server group SECURE v3 priv\n",
            [],
        ),
        (
            "management.ntp_not_configured",
            "hostname edge\n",
            "hostname edge\nntp server 192.0.2.10\n",
            [],
        ),
        (
            "management.syslog_not_configured",
            "hostname edge\n",
            "hostname edge\nlogging host 192.0.2.20\n",
            [],
        ),
    ),
)
def test_each_observability_rule_has_positive_and_negative_case(
    rule_id: str,
    violating_text: str,
    compliant_text: str,
    affected_lines: list[int],
) -> None:
    rule = next(rule for rule in OBSERVABILITY_RULES if rule.rule_id == rule_id)
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
    assert positive[0].affected_lines == affected_lines
    assert positive[0].remediation == rule.remediation
    assert positive[0].references == list(rule.references)


def test_policy_catalog_has_unique_rule_ids() -> None:
    rule_ids = [rule.rule_id for rule in POLICY_RULES]

    assert len(POLICY_RULES) == 18
    assert len(rule_ids) == len(set(rule_ids))


@pytest.mark.parametrize(
    (
        "rule_id",
        "violating_text",
        "compliant_text",
        "affected_lines",
        "evidence_lines",
    ),
    (
        (
            "acl.empty",
            "hostname edge\nip access-list extended EMPTY\n!\n",
            "hostname edge\nip access-list extended FILTER\n 10 deny ip any any\n",
            [2],
            [[2]],
        ),
        (
            "acl.unrestricted_permit",
            "hostname edge\nip access-list extended OPEN\n 10 permit ip any any\n",
            (
                "hostname edge\nip access-list extended FILTER\n"
                " 10 permit tcp host 192.0.2.10 host 192.0.2.1 eq ssh\n"
            ),
            [3],
            [[3]],
        ),
        (
            "acl.telnet_permitted",
            (
                "hostname edge\nip access-list extended MGMT\n"
                " 10 permit tcp host 192.0.2.10 host 192.0.2.1 eq telnet\n"
            ),
            (
                "hostname edge\nip access-list extended MGMT\n"
                " 10 permit tcp host 192.0.2.10 host 192.0.2.1 eq ssh\n"
            ),
            [3],
            [[3]],
        ),
        (
            "acl.management_access_from_any",
            (
                "set system host-name edge\n"
                "set firewall family inet filter MGMT term SSH from source-address any\n"
                "set firewall family inet filter MGMT term SSH from protocol tcp\n"
                "set firewall family inet filter MGMT term SSH from destination-port ssh\n"
                "set firewall family inet filter MGMT term SSH then accept\n"
            ),
            (
                "set system host-name edge\n"
                "set firewall family inet filter MGMT term SSH from source-address "
                "192.0.2.0/24\n"
                "set firewall family inet filter MGMT term SSH from protocol tcp\n"
                "set firewall family inet filter MGMT term SSH from destination-port ssh\n"
                "set firewall family inet filter MGMT term SSH then accept\n"
            ),
            [2, 3, 4, 5],
            [[2], [3], [4], [5]],
        ),
    ),
)
def test_each_access_control_rule_has_positive_and_negative_case(
    rule_id: str,
    violating_text: str,
    compliant_text: str,
    affected_lines: list[int],
    evidence_lines: list[list[int]],
) -> None:
    rule = next(rule for rule in ACCESS_CONTROL_RULES if rule.rule_id == rule_id)
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
    assert positive[0].affected_lines == affected_lines
    assert [
        evidence.source_location.source_lines
        for evidence in positive[0].evidence
        if evidence.source_location is not None
    ] == evidence_lines
    assert positive[0].remediation == rule.remediation
    assert positive[0].references == list(rule.references)


@pytest.mark.parametrize(
    (
        "rule_id",
        "violating_text",
        "compliant_text",
        "affected_lines",
        "evidence_lines",
    ),
    (
        (
            "bgp.router_id_missing",
            (
                "hostname edge\nrouter bgp 65001\n"
                " neighbor 192.0.2.2 remote-as 65002\n"
            ),
            (
                "hostname edge\nrouter bgp 65001\n bgp router-id 192.0.2.1\n"
                " neighbor 192.0.2.2 remote-as 65002\n"
            ),
            [2],
            [[2]],
        ),
        (
            "bgp.neighbor_is_local_address",
            (
                "hostname edge\ninterface GigabitEthernet0/0\n"
                " ip address 192.0.2.1 255.255.255.0\n!\nrouter bgp 65001\n"
                " bgp router-id 192.0.2.1\n"
                " neighbor 192.0.2.1 remote-as 65002\n"
            ),
            (
                "hostname edge\ninterface GigabitEthernet0/0\n"
                " ip address 192.0.2.1 255.255.255.0\n!\nrouter bgp 65001\n"
                " bgp router-id 192.0.2.1\n"
                " neighbor 192.0.2.2 remote-as 65002\n"
            ),
            [3, 7],
            [[3], [7]],
        ),
        (
            "ospf.router_id_missing",
            (
                "set system host-name edge\n"
                "set protocols ospf area 0 interface ge-0/0/0.0\n"
            ),
            (
                "set system host-name edge\n"
                "set routing-options router-id 192.0.2.1\n"
                "set protocols ospf area 0 interface ge-0/0/0.0\n"
            ),
            [2],
            [[2]],
        ),
        (
            "routing.default_route_discarded",
            "hostname edge\nip route 0.0.0.0 0.0.0.0 Null0\n",
            "hostname edge\nip route 198.51.100.0 255.255.255.0 Null0\n",
            [2],
            [[2]],
        ),
    ),
)
def test_each_routing_rule_has_positive_and_negative_case(
    rule_id: str,
    violating_text: str,
    compliant_text: str,
    affected_lines: list[int],
    evidence_lines: list[list[int]],
) -> None:
    rule = next(rule for rule in ROUTING_RULES if rule.rule_id == rule_id)
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
    assert positive[0].affected_lines == affected_lines
    assert [
        evidence.source_location.source_lines
        for evidence in positive[0].evidence
        if evidence.source_location is not None
    ] == evidence_lines
    assert positive[0].remediation == rule.remediation
    assert positive[0].references == list(rule.references)


@pytest.mark.parametrize(
    (
        "rule_id",
        "violating_text",
        "compliant_text",
        "affected_lines",
        "evidence_lines",
    ),
    (
        (
            "interface.access_vlan_missing",
            (
                "hostname edge\ninterface GigabitEthernet0/1\n"
                " switchport mode access\n"
            ),
            (
                "hostname edge\ninterface GigabitEthernet0/1\n"
                " switchport mode access\n switchport access vlan 10\n"
            ),
            [3],
            [[3]],
        ),
        (
            "interface.trunk_vlans_unrestricted",
            (
                "hostname edge\ninterface GigabitEthernet0/1\n"
                " switchport mode trunk\n switchport trunk allowed vlan all\n"
            ),
            (
                "hostname edge\ninterface GigabitEthernet0/1\n"
                " switchport mode trunk\n switchport trunk allowed vlan 10,20\n"
            ),
            [3, 4],
            [[3], [4]],
        ),
        (
            "interface.switchport_mode_conflict",
            (
                "hostname edge\ninterface GigabitEthernet0/1\n"
                " switchport mode trunk\n switchport access vlan 10\n"
            ),
            (
                "hostname edge\ninterface GigabitEthernet0/1\n"
                " switchport mode trunk\n switchport trunk allowed vlan 10\n"
            ),
            [3, 4],
            [[3], [4]],
        ),
    ),
)
def test_each_layer2_rule_has_positive_and_negative_case(
    rule_id: str,
    violating_text: str,
    compliant_text: str,
    affected_lines: list[int],
    evidence_lines: list[list[int]],
) -> None:
    rule = next(rule for rule in LAYER2_RULES if rule.rule_id == rule_id)
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
    assert positive[0].affected_lines == affected_lines
    assert [
        evidence.source_location.source_lines
        for evidence in positive[0].evidence
        if evidence.source_location is not None
    ] == evidence_lines
    assert positive[0].remediation == rule.remediation
    assert positive[0].references == list(rule.references)


def test_trunk_without_allowed_list_is_reported_as_absence_based() -> None:
    config = parse_configuration(
        "hostname edge\ninterface GigabitEthernet0/1\n switchport mode trunk\n",
        filename="device.cfg",
        collected_at=COLLECTED_AT,
    )
    rule = next(
        rule
        for rule in LAYER2_RULES
        if rule.rule_id == "interface.trunk_vlans_unrestricted"
    )

    finding = evaluate_policies(config, device_id=DEVICE_ID, rules=(rule,))[0]

    assert finding.affected_lines == [3]
    assert finding.limitations == [
        "The unrestricted VLAN set is inferred from the absence of supported restriction syntax."
    ]
