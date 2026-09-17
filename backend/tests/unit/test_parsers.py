"""Focused parser behavior tests beyond the golden snapshots."""

from datetime import datetime
from pathlib import Path

from app.domain import Vendor
from app.parsers import parse_configuration

SAMPLES_ROOT = Path(__file__).resolve().parents[3] / "samples"


def _parse(path: Path, collected_at: datetime):  # type: ignore[no-untyped-def]
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
    assert config.management.provenance["ssh_enabled"].source_lines == [4, 9]
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


def test_junos_hierarchical_management(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "juniper_junos" / "edge-secure.conf", collected_at)

    assert config.device.vendor is Vendor.JUNIPER
    assert config.device.hostname == "juniper-edge-01"
    assert config.management.ssh_enabled is True
    assert config.management.aaa_enabled is True
    assert config.management.snmp_versions == ["v3"]
    assert config.management.syslog_servers == ["192.0.2.20"]
    assert config.unparsed_fragments == []


def test_junos_set_style_and_unknown_command(collected_at: datetime) -> None:
    config = _parse(SAMPLES_ROOT / "juniper_junos" / "access-set.conf", collected_at)

    assert config.device.hostname == "juniper-access-01"
    assert config.management.telnet_enabled is True
    assert config.management.snmp_versions == ["v1", "v2c"]
    assert config.management.ntp_servers == ["192.0.2.11"]
    assert [item.location.source_lines for item in config.unparsed_fragments] == [[6]]
    assert config.parser_confidence < 1.0
