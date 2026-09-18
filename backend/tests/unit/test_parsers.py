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
    assert config.management.provenance["ssh_enabled"].source_lines == [4, 15]
    assert len(config.interfaces) == 1
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
    assert interface.provenance["enabled"].source_lines == [12]
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


def test_junos_hierarchical_management(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "juniper_junos" / "edge-secure.conf", collected_at)

    assert config.device.vendor is Vendor.JUNIPER
    assert config.device.hostname == "juniper-edge-01"
    assert config.management.ssh_enabled is True
    assert config.management.aaa_enabled is True
    assert config.management.snmp_versions == ["v3"]
    assert config.management.syslog_servers == ["192.0.2.20"]
    assert len(config.interfaces) == 1
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
    assert config.unparsed_fragments == []


def test_junos_set_style_and_unknown_command(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "juniper_junos" / "access-set.conf", collected_at)

    assert config.device.hostname == "juniper-access-01"
    assert config.management.telnet_enabled is True
    assert config.management.snmp_versions == ["v1", "v2c"]
    assert config.management.ntp_servers == ["192.0.2.11"]
    assert [item.location.source_lines for item in config.unparsed_fragments] == [[9]]
    assert len(config.interfaces) == 1
    interface = config.interfaces[0]
    assert interface.name == "ge-0/0/1"
    assert interface.unit == "0"
    assert interface.description == "User access"
    assert interface.enabled is False
    assert [address.address for address in interface.addresses] == ["192.0.2.9/30"]
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
