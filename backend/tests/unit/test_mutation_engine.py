"""Tests for deterministic, reversible synthetic anomaly generation."""

import hashlib
from datetime import UTC, datetime

import pytest
from app.domain import Vendor

from ml.datasets import ImportedDatasetRecord
from ml.mutation import (
    MutationNotApplicableError,
    MutationType,
    MutationValidationError,
    MutationValidationStatus,
    count_synthetic_anomaly_labels,
    list_applicable_mutations,
    mutate_configuration,
    reverse_mutation,
)

CISCO_TEXT = """version 17.9
hostname host-000000000001
aaa new-model
ip ssh version 2
snmp-server group NMS v3 priv
ntp server 198.51.100.10
logging host 198.51.100.20
vlan 10
 name USERS
!
vlan 20
 name SERVERS
!
interface GigabitEthernet0/1
 description User access
 ip address 198.51.100.1 255.255.255.0
 switchport mode access
 switchport access vlan 10
 no shutdown
!
interface GigabitEthernet0/2
 description Server access
 ip address 198.51.101.1 255.255.255.0
 switchport mode access
 switchport access vlan 20
 no shutdown
!
line vty 0 4
 transport input ssh
ip access-list extended MGMT-IN
 10 permit tcp 198.51.100.0 0.0.0.255 host 198.51.100.1 eq ssh log
 20 deny ip any any log
!
ip route 203.0.113.0 255.255.255.0 198.51.100.254
router bgp 65001
 bgp router-id 198.51.100.1
 neighbor 198.51.100.2 remote-as 65002
 neighbor 198.51.100.2 description Transit
!
router ospf 10
 router-id 198.51.100.1
 network 198.51.100.0 0.0.0.255 area 0
!
route-map EXPORT permit 10
 match ip address prefix-list TRUSTED
!
route-map EXPORT permit 20
 set metric 50
!
end
"""


JUNOS_SET_TEXT = """set system host-name host-000000000002
set system services ssh
set system authentication-order [ radius password ]
set system ntp server 198.51.100.10
set system syslog host 198.51.100.20 any notice
set snmp v3 usm local-engine user user-000000000001
set vlans USERS vlan-id 10
set vlans SERVERS vlan-id 20
set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members USERS
set interfaces ge-0/0/2 unit 0 family inet address 198.51.101.1/24
set interfaces ge-0/0/2 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members SERVERS
set firewall family inet filter MGMT-IN term ALLOW-SSH from source-address 198.51.100.0/24
set firewall family inet filter MGMT-IN term ALLOW-SSH from protocol tcp
set firewall family inet filter MGMT-IN term ALLOW-SSH from destination-port ssh
set firewall family inet filter MGMT-IN term ALLOW-SSH then accept
set firewall family inet filter MGMT-IN term DENY-REST then discard
set routing-options static route 203.0.113.0/24 next-hop 198.51.100.254
set routing-options autonomous-system 65001
set routing-options router-id 198.51.100.1
set protocols bgp group TRANSIT type external
set protocols bgp group TRANSIT peer-as 65002
set protocols bgp group TRANSIT neighbor 198.51.100.2
set protocols ospf area 0 interface ge-0/0/1.0
"""


def _record(text: str, vendor: Vendor, *, record_id: str = "record-001") -> ImportedDatasetRecord:
    digest = hashlib.sha256(text.encode()).hexdigest()
    return ImportedDatasetRecord(
        source_id="lab-source",
        record_id=record_id,
        network_id="network-000000000001",
        site_id="site-000000000001",
        device_id="device-000000000001",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        vendor_hint=vendor,
        device_role="edge-router",
        raw_sha256=digest,
        sanitized_sha256=digest,
        sanitized_text=text,
        raw_byte_count=len(text.encode()),
        replacements={},
        sanitization_version="config-sanitizer-0.1.0",
    )


@pytest.mark.parametrize("mutation_type", list(MutationType))
def test_every_required_mutation_is_reversible_on_cisco(
    mutation_type: MutationType,
) -> None:
    record = _record(CISCO_TEXT, Vendor.CISCO)

    sample = mutate_configuration(record, (mutation_type,), seed=17)

    assert sample.labels[0].mutation_type is mutation_type
    assert sample.labels[0].synthetic is True
    assert sample.labels[0].real_confirmed is False
    assert sample.original_sha256 == record.sanitized_sha256
    assert sample.mutated_text != record.sanitized_text
    expected_status = (
        MutationValidationStatus.PARTIAL
        if mutation_type is MutationType.ROUTE_MAP_ORDER_CHANGE
        else MutationValidationStatus.PASSED
    )
    assert sample.syntax_validation.status is expected_status
    assert sample.syntax_validation.introduced_warning_count == 0
    assert sample.syntax_validation.introduced_unparsed_fragment_count == 0
    assert sample.formal_validation.status is MutationValidationStatus.NOT_RUN
    assert reverse_mutation(sample, sample.mutated_text) == record.sanitized_text
    assert record.sanitized_text == CISCO_TEXT


def test_mutation_is_deterministic_and_seed_selects_a_variant() -> None:
    record = _record(CISCO_TEXT, Vendor.CISCO)

    first = mutate_configuration(record, (MutationType.TELNET_ENABLED,), seed=1)
    repeated = mutate_configuration(record, (MutationType.TELNET_ENABLED,), seed=1)
    variants = {
        mutate_configuration(record, (MutationType.TELNET_ENABLED,), seed=seed).mutated_text
        for seed in range(12)
    }

    assert first == repeated
    assert len(variants) >= 2


def test_linked_mutations_have_distinct_labels_and_reverse_exactly() -> None:
    record = _record(CISCO_TEXT, Vendor.CISCO)
    types = (
        MutationType.AAA_DISABLED,
        MutationType.TELNET_ENABLED,
        MutationType.MISSING_NTP_SYSLOG,
    )

    sample = mutate_configuration(record, types, seed=41)

    assert tuple(label.mutation_type for label in sample.labels) == types
    assert tuple(operation.mutation_type for operation in sample.operations) == types
    assert count_synthetic_anomaly_labels((sample,)) == 3
    assert reverse_mutation(sample, sample.mutated_text) == CISCO_TEXT

    with pytest.raises(ValueError, match="unique IDs"):
        count_synthetic_anomaly_labels((sample, sample))


@pytest.mark.parametrize(
    "mutation_type",
    [
        MutationType.AAA_DISABLED,
        MutationType.TELNET_ENABLED,
        MutationType.SNMP_DOWNGRADE,
        MutationType.PERMISSIVE_ACL,
        MutationType.MISSING_ACL_ENTRY,
        MutationType.VLAN_MISMATCH,
        MutationType.INCORRECT_ACCESS_TRUNK_MODE,
        MutationType.BGP_REMOTE_AS_MISMATCH,
        MutationType.MISSING_BGP_NEIGHBOR,
        MutationType.OSPF_AREA_MISMATCH,
        MutationType.REMOVED_STATIC_ROUTE,
        MutationType.MANAGEMENT_EXPOSURE,
        MutationType.MISSING_NTP_SYSLOG,
        MutationType.CONFLICTING_IP_ADDRESS,
    ],
)
def test_junos_set_mutations_are_parser_validated(mutation_type: MutationType) -> None:
    record = _record(JUNOS_SET_TEXT, Vendor.JUNIPER)

    sample = mutate_configuration(record, (mutation_type,), seed=9)

    assert sample.vendor is Vendor.JUNIPER
    assert sample.syntax_validation.parser == "juniper_junos"
    assert reverse_mutation(sample, sample.mutated_text) == JUNOS_SET_TEXT


def test_applicable_mutations_excludes_vendor_specific_recipe() -> None:
    record = _record(JUNOS_SET_TEXT, Vendor.JUNIPER)

    applicable = list_applicable_mutations(record, seed=3)

    assert MutationType.ROUTE_MAP_ORDER_CHANGE not in applicable
    assert MutationType.BGP_REMOTE_AS_MISMATCH in applicable
    assert len(applicable) == len(MutationType) - 1


def test_hierarchical_junos_is_rejected_until_structural_edits_are_supported() -> None:
    text = "system {\n    host-name host-000000000003;\n    services { ssh; }\n}\n"
    record = _record(text, Vendor.JUNIPER)

    with pytest.raises(MutationNotApplicableError, match="set syntax only"):
        mutate_configuration(record, (MutationType.TELNET_ENABLED,))


def test_hash_and_reverse_context_tampering_are_rejected() -> None:
    record = _record(CISCO_TEXT, Vendor.CISCO)
    invalid = record.model_copy(update={"sanitized_text": f"{CISCO_TEXT}! changed\n"})

    with pytest.raises(ValueError, match="does not match"):
        mutate_configuration(invalid, (MutationType.AAA_DISABLED,))

    sample = mutate_configuration(record, (MutationType.AAA_DISABLED,))
    with pytest.raises(MutationValidationError, match="does not match"):
        reverse_mutation(sample, f"{sample.mutated_text}! changed\n")
