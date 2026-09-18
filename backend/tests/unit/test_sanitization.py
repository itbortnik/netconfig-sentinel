"""Tests for deterministic removal of sensitive configuration values."""

from ipaddress import IPv4Address, IPv4Network

from ml.preprocessing import (
    SanitizationPolicy,
    pseudonymize_identifier,
    sanitize_configuration,
)

PSEUDONYMIZATION_KEY = b"unit-test-pseudonymization-key"


def test_cisco_sensitive_values_and_pem_material_are_removed() -> None:
    source = """hostname edge-prod-01
username admin privilege 15 secret 9 SUPERHASH
enable secret 9 ENABLEHASH
snmp-server community public RO
snmp-server user monitor GROUP v3 auth sha AUTH-PASS priv aes 128 PRIV-PASS
ip domain name corp.example
snmp-server contact Jane Doe <jane@example.com>
snmp-server location DC-1 Rack-2
key 7 TACACS-KEY
interface GigabitEthernet0/1
 ip address 10.20.30.1 255.255.255.0
crypto pki certificate chain EDGE-TRUSTPOINT
 certificate self-signed 01
  NATIVE-CERTIFICATE-MATERIAL
  quit
-----BEGIN PRIVATE KEY-----
PRIVATE-MATERIAL
-----END PRIVATE KEY-----
"""

    result = sanitize_configuration(
        source,
        topology_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )

    for sensitive in (
        "edge-prod-01",
        "admin",
        "SUPERHASH",
        "ENABLEHASH",
        "public",
        "monitor",
        "AUTH-PASS",
        "PRIV-PASS",
        "corp.example",
        "Jane Doe",
        "jane@example.com",
        "DC-1",
        "TACACS-KEY",
        "EDGE-TRUSTPOINT",
        "NATIVE-CERTIFICATE-MATERIAL",
        "PRIVATE-MATERIAL",
        "10.20.30.1",
    ):
        assert sensitive not in result.text
    assert "255.255.255.0" in result.text
    assert "-----BEGIN PRIVATE KEY-----" in result.text
    assert "-----END PRIVATE KEY-----" in result.text
    assert "<redacted-material>" in result.text
    assert result.text.count("\n") == source.count("\n")
    assert result.replacements == {
        "hostname": 1,
        "username": 2,
        "secret": 5,
        "snmp_community": 1,
        "domain": 1,
        "contact": 2,
        "ip_address": 1,
        "certificate_identity": 2,
        "key_or_certificate": 2,
    }


def test_junos_quotes_and_statement_boundaries_are_preserved() -> None:
    source = """set system host-name "edge-junos";
set system login user alice authentication encrypted-password "$6$HASH";
set snmp community "public-ro" authorization read-only;
set snmp v3 usm local-engine user snmpadmin authentication-sha authentication-password "SNMP-AUTH";
set security ike policy remote pre-shared-key ascii-text "VPN-SECRET";
set snmp contact "Jane Doe";
"""

    result = sanitize_configuration(
        source,
        topology_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )

    for sensitive in (
        "edge-junos",
        "alice",
        "$6$HASH",
        "public-ro",
        "snmpadmin",
        "SNMP-AUTH",
        "VPN-SECRET",
        "Jane Doe",
    ):
        assert sensitive not in result.text
    assert 'host-name "host-' in result.text
    assert 'encrypted-password "<redacted-secret>";' in result.text
    assert 'community "<redacted-community>"' in result.text
    assert 'ascii-text "<redacted-secret>";' in result.text
    assert result.text.endswith("set snmp contact <redacted-contact>;\n")


def test_ip_aliases_are_deterministic_scoped_and_prefix_preserving() -> None:
    source = "ip address 10.20.30.1 255.255.255.0\nneighbor 10.20.30.2\n"

    first = sanitize_configuration(
        source,
        topology_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )
    repeated = sanitize_configuration(
        source,
        topology_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )
    other_topology = sanitize_configuration(
        source,
        topology_id="source-a/network-b",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )

    first_lines = first.text.splitlines()
    first_address = IPv4Address(first_lines[0].split()[2])
    second_address = IPv4Address(first_lines[1].split()[1])
    other_address = IPv4Address(other_topology.text.splitlines()[0].split()[2])
    assert first == repeated
    assert first_address != IPv4Address("10.20.30.1")
    assert second_address != IPv4Address("10.20.30.2")
    assert other_address != first_address
    assert IPv4Network((first_address, 30), strict=False) == IPv4Network(
        (second_address, 30), strict=False
    )
    assert first_lines[0].split()[3] == "255.255.255.0"


def test_ip_pseudonymization_can_be_disabled_by_reviewed_policy() -> None:
    source = "neighbor 192.0.2.10\n"

    result = sanitize_configuration(
        source,
        topology_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
        policy=SanitizationPolicy(pseudonymize_ip_addresses=False),
    )

    assert result.text == source
    assert result.replacements == {}


def test_identifier_aliases_are_stable_and_scope_separated() -> None:
    first = pseudonymize_identifier(
        "edge-prod-01",
        kind="device",
        scope_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )
    repeated = pseudonymize_identifier(
        "edge-prod-01",
        kind="device",
        scope_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )
    other_scope = pseudonymize_identifier(
        "edge-prod-01",
        kind="device",
        scope_id="source-b/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )

    assert first == repeated
    assert first.startswith("device-")
    assert "edge-prod-01" not in first
    assert first != other_scope


def test_password_policy_is_not_mistaken_for_a_credential() -> None:
    source = "set system login password minimum-length 14;\n"

    result = sanitize_configuration(
        source,
        topology_id="source-a/network-a",
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )

    assert result.text == source
    assert result.replacements == {}
