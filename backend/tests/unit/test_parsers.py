"""Focused parser behavior tests beyond the golden snapshots."""

from datetime import datetime
from pathlib import Path

from app.domain import CanonicalConfig, Vendor
from app.parsers import parse_configuration

SAMPLES_ROOT = Path(__file__).resolve().parents[3] / "samples"


def _parse(path: Path, collected_at: datetime) -> CanonicalConfig:
    return parse_configuration(
        path.read_text(encoding="utf-8"),
        filename=path.name,
        collected_at=collected_at,
    )


def test_cisco_management_and_provenance(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "cisco_ios" / "edge-secure.cfg", collected_at)

    assert config.device.vendor is Vendor.CISCO
    assert config.device.hostname == "cisco-edge-01"
    assert config.management.ssh_enabled is True
    assert config.management.telnet_enabled is False
    assert config.management.aaa_enabled is True
    assert config.management.snmp_versions == ["v3"]
    assert config.management.ntp_servers == ["192.0.2.10"]
    assert config.management.provenance["ssh_enabled"].source_lines == [4, 31]
    assert len(config.interfaces) == 2
    interface = config.interfaces[0]
    assert interface.name == "GigabitEthernet0/0"
    assert interface.unit is None
    assert interface.description == "WAN uplink"
    assert interface.enabled is True
    assert [address.address for address in interface.addresses] == [
        "192.0.2.1/30",
        "2001:db8:1::1/64",
    ]
    assert [address.family for address in interface.addresses] == ["ipv4", "ipv6"]
    assert interface.provenance["enabled"].source_lines == [21]
    trunk = config.interfaces[1]
    assert trunk.name == "GigabitEthernet0/1"
    assert trunk.switchport_mode == "trunk"
    assert trunk.native_vlan is not None
    assert trunk.native_vlan.vlan_id == 99
    assert trunk.allowed_vlans is not None
    assert trunk.allowed_vlans.vlan_ids == [10, 20, 99]
    assert [(vlan.vlan_id, vlan.name) for vlan in config.vlans] == [
        (10, "USERS"),
        (20, "SERVERS"),
        (99, "NATIVE"),
    ]
    acl = config.acls[0]
    assert (acl.name, acl.family, acl.kind) == ("MGMT-IN", "ipv4", "extended")
    assert len(acl.rules) == 2
    assert acl.rules[0].source_addresses == ["192.0.2.0/24"]
    assert acl.rules[0].destination_addresses == ["192.0.2.1/32"]
    assert acl.rules[0].destination_ports == ["eq:ssh"]
    assert acl.rules[0].options == ["log"]
    assert acl.rules[0].provenance["rule"].source_lines == [33]
    assert [(item.name, item.family) for item in config.prefix_lists] == [
        ("TRUSTED", "ipv4"),
        ("V6-TRUSTED", "ipv6"),
    ]
    assert config.prefix_lists[0].rules[0].sequence == 10
    assert config.prefix_lists[0].rules[0].le == 32
    assert config.unparsed_fragments == []


def test_unknown_cisco_command_is_preserved_and_reduces_confidence(
    collected_at: datetime,
) -> None:
    config = _parse(SAMPLES_ROOT / "cisco_ios" / "access-legacy.cfg", collected_at)

    assert [item.raw_text for item in config.unparsed_fragments] == [
        "clock timezone UTC 0 0"
    ]
    assert config.parser_confidence < 1.0
    assert config.management.telnet_enabled is True
    assert config.interfaces[0].name == "GigabitEthernet0/1"
    assert config.interfaces[0].enabled is False
    assert config.interfaces[0].addresses == []
    assert config.interfaces[0].switchport_mode == "access"
    assert config.interfaces[0].access_vlan is not None
    assert config.interfaces[0].access_vlan.vlan_id == 10
    assert config.vlans[0].name == "USERS"
    assert config.acls[0].kind == "standard"
    assert config.acls[0].rules[0].source_addresses == ["192.0.2.10/32"]
    assert config.prefix_lists[0].rules[0].prefix == "198.51.100.0/24"


def test_junos_hierarchical_management(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "juniper_junos" / "edge-secure.conf", collected_at)

    assert config.device.vendor is Vendor.JUNIPER
    assert config.device.hostname == "juniper-edge-01"
    assert config.management.ssh_enabled is True
    assert config.management.aaa_enabled is True
    assert config.management.snmp_versions == ["v3"]
    assert config.management.syslog_servers == ["192.0.2.20"]
    assert len(config.interfaces) == 2
    interface = config.interfaces[0]
    assert interface.name == "ge-0/0/0"
    assert interface.unit == "0"
    assert interface.description == "WAN uplink"
    assert interface.enabled is None
    assert [address.address for address in interface.addresses] == [
        "192.0.2.5/30",
        "2001:db8:2::1/64",
    ]
    assert interface.provenance["description"].source_lines == [18]
    trunk = config.interfaces[1]
    assert trunk.name == "ge-0/0/1"
    assert trunk.unit == "0"
    assert trunk.switchport_mode == "trunk"
    assert trunk.native_vlan is not None
    assert trunk.native_vlan.vlan_id == 99
    assert trunk.allowed_vlans is not None
    assert trunk.allowed_vlans.vlan_ids == [10, 20, 99]
    assert trunk.allowed_vlans.vlan_names == ["USERS", "SERVERS", "NATIVE"]
    assert [(vlan.vlan_id, vlan.name) for vlan in config.vlans] == [
        (10, "USERS"),
        (20, "SERVERS"),
        (99, "NATIVE"),
    ]
    acl = config.acls[0]
    assert (acl.name, acl.family, acl.kind) == (
        "MGMT-IN",
        "ipv4",
        "firewall_filter",
    )
    assert [rule.term for rule in acl.rules] == ["ALLOW-SSH", "DENY-REST"]
    assert acl.rules[0].action == "permit"
    assert acl.rules[0].protocol == "tcp"
    assert acl.rules[0].source_addresses == ["192.0.2.0/24"]
    assert acl.rules[0].destination_ports == ["ssh"]
    assert acl.rules[1].action == "deny"
    assert [rule.prefix for rule in config.prefix_lists[0].rules] == [
        "192.0.2.0/24",
        "198.51.100.0/24",
    ]
    assert config.unparsed_fragments == []


def test_junos_set_style_and_unknown_command(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "juniper_junos" / "access-set.conf", collected_at)

    assert config.device.hostname == "juniper-access-01"
    assert config.management.telnet_enabled is True
    assert config.management.snmp_versions == ["v1", "v2c"]
    assert config.management.ntp_servers == ["192.0.2.11"]
    assert [item.location.source_lines for item in config.unparsed_fragments] == [[13]]
    assert len(config.interfaces) == 2
    interface = config.interfaces[0]
    assert interface.name == "ge-0/0/1"
    assert interface.unit == "0"
    assert interface.description == "User access"
    assert interface.enabled is False
    assert [address.address for address in interface.addresses] == ["192.0.2.9/30"]
    access = config.interfaces[1]
    assert access.name == "ge-0/0/2"
    assert access.switchport_mode == "access"
    assert access.access_vlan is not None
    assert access.access_vlan.name == "USERS"
    assert access.access_vlan.vlan_id == 10
    assert [(vlan.vlan_id, vlan.name) for vlan in config.vlans] == [(10, "USERS")]
    assert [rule.action for rule in config.acls[0].rules] == ["permit", "deny"]
    assert config.acls[0].rules[0].destination_ports == ["ssh"]
    assert config.prefix_lists[0].rules[0].prefix == "192.0.2.0/24"
    assert config.parser_confidence < 1.0


def test_cisco_address_family_mismatch_is_preserved(collected_at: datetime) -> None:
    text = "\n".join(
        [
            "hostname invalid-cisco",
            "interface GigabitEthernet0/0",
            " ip address 2001:db8::1 64",
        ]
    )

    config = parse_configuration(
        text, filename="invalid-cisco.cfg", collected_at=collected_at
    )

    assert config.interfaces[0].addresses == []
    assert config.parse_warnings == ["invalid ipv4 interface address at line 3"]
    assert [fragment.raw_text.strip() for fragment in config.unparsed_fragments] == [
        "ip address 2001:db8::1 64"
    ]


def test_junos_address_family_mismatch_is_preserved(collected_at: datetime) -> None:
    text = "\n".join(
        [
            "set system host-name invalid-junos",
            "set interfaces ge-0/0/0 unit 0 family inet address 2001:db8::1/64",
        ]
    )

    config = parse_configuration(
        text, filename="invalid-junos.conf", collected_at=collected_at
    )

    assert config.interfaces[0].addresses == []
    assert config.parse_warnings == ["invalid ipv4 interface address at line 2"]
    assert [fragment.raw_text for fragment in config.unparsed_fragments] == [text.splitlines()[1]]


def test_cisco_trunk_vlan_range_is_normalized(collected_at: datetime) -> None:
    text = "\n".join(
        [
            "hostname range-switch",
            "interface GigabitEthernet0/1",
            " switchport mode trunk",
            " switchport trunk allowed vlan 10,20-22",
        ]
    )

    config = parse_configuration(
        text, filename="range-switch.cfg", collected_at=collected_at
    )

    allowed = config.interfaces[0].allowed_vlans
    assert allowed is not None
    assert allowed.vlan_ids == [10, 20, 21, 22]


def test_invalid_cisco_vlan_is_preserved(collected_at: datetime) -> None:
    text = "hostname invalid-vlan\nvlan 4095"

    config = parse_configuration(
        text, filename="invalid-vlan.cfg", collected_at=collected_at
    )

    assert config.vlans == []
    assert config.parse_warnings == ["invalid VLAN identifier at line 2"]
    assert [fragment.raw_text for fragment in config.unparsed_fragments] == ["vlan 4095"]


def test_invalid_cisco_prefix_list_is_preserved(collected_at: datetime) -> None:
    text = "hostname invalid-prefix\nip prefix-list BAD permit 192.0.2.0/24 ge 16"

    config = parse_configuration(
        text, filename="invalid-prefix.cfg", collected_at=collected_at
    )

    assert config.prefix_lists == []
    assert config.parse_warnings == ["invalid prefix-list entry at line 2"]
    assert [fragment.raw_text for fragment in config.unparsed_fragments] == [
        "ip prefix-list BAD permit 192.0.2.0/24 ge 16"
    ]


def test_incomplete_junos_firewall_term_is_preserved(collected_at: datetime) -> None:
    text = "\n".join(
        [
            "set system host-name incomplete-filter",
            "set firewall family inet filter INPUT term NO-ACTION from protocol tcp",
        ]
    )

    config = parse_configuration(
        text, filename="incomplete-filter.conf", collected_at=collected_at
    )

    assert config.acls[0].rules == []
    assert config.parse_warnings == [
        "firewall term INPUT/NO-ACTION has no supported action"
    ]
    assert [fragment.raw_text for fragment in config.unparsed_fragments] == [
        text.splitlines()[1]
    ]
