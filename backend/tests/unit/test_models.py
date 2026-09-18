"""Validation tests for public domain contracts."""

from uuid import uuid4

import pytest
from app.domain import (
    AclConfig,
    AclRule,
    Finding,
    InterfaceAddress,
    PrefixListConfig,
    PrefixListRule,
    Severity,
    SourceLocation,
    StaticRouteConfig,
    VlanSet,
)
from app.domain.models import ConfigSource
from pydantic import ValidationError

VALID_HASH = "0" * 64


def test_source_location_requires_ordered_unique_positive_lines() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(
            source_lines=[2, 1, 2],
            raw_text_hash=VALID_HASH,
            parser_confidence=1.0,
        )


def test_source_rejects_paths(collected_at: object) -> None:
    with pytest.raises(ValidationError):
        ConfigSource(
            filename="../router.cfg",
            sha256=VALID_HASH,
            collected_at=collected_at,
        )


def test_finding_keeps_severity_confidence_and_anomaly_score_separate() -> None:
    finding = Finding(
        finding_id=uuid4(),
        device_id=uuid4(),
        detector="policy_engine",
        category="management.telnet_enabled",
        title="Telnet is enabled",
        severity=Severity.HIGH,
        confidence=1.0,
        anomaly_score=0.0,
        affected_lines=[6],
        model_version="rules-0.1.0",
    )

    assert finding.severity is Severity.HIGH
    assert finding.confidence == 1.0
    assert finding.anomaly_score == 0.0


def test_interface_address_is_canonicalized_and_family_checked() -> None:
    address = InterfaceAddress(
        address="192.0.2.1/255.255.255.252",
        family="ipv4",
        provenance=SourceLocation(
            source_lines=[10],
            raw_text_hash=VALID_HASH,
            parser_confidence=1.0,
        ),
    )

    assert address.address == "192.0.2.1/30"

    with pytest.raises(ValidationError, match="family must be ipv4"):
        InterfaceAddress(
            address="192.0.2.1/30",
            family="ipv6",
            provenance=address.provenance,
        )


def test_vlan_set_requires_sorted_unique_valid_identifiers() -> None:
    provenance = SourceLocation(
        source_lines=[12],
        raw_text_hash=VALID_HASH,
        parser_confidence=1.0,
    )

    with pytest.raises(ValidationError, match="sorted and unique"):
        VlanSet(vlan_ids=[20, 10, 10], provenance=provenance)

    with pytest.raises(ValidationError, match="between 1 and 4094"):
        VlanSet(vlan_ids=[4095], provenance=provenance)


def test_prefix_list_rule_canonicalizes_and_validates_length_range() -> None:
    provenance = SourceLocation(
        source_lines=[15],
        raw_text_hash=VALID_HASH,
        parser_confidence=1.0,
    )
    rule = PrefixListRule(
        action="permit",
        prefix="192.0.2.7/24",
        ge=25,
        le=32,
        provenance=provenance,
    )

    assert rule.prefix == "192.0.2.0/24"

    with pytest.raises(ValidationError, match="between 24 and 32"):
        PrefixListRule(
            action="permit",
            prefix="192.0.2.0/24",
            ge=16,
            provenance=provenance,
        )


def test_acl_and_prefix_list_reject_mixed_address_families() -> None:
    provenance = SourceLocation(
        source_lines=[20],
        raw_text_hash=VALID_HASH,
        parser_confidence=1.0,
    )

    with pytest.raises(ValidationError, match="ACL address family must be ipv4"):
        AclConfig(
            name="MIXED",
            family="ipv4",
            kind="extended",
            rules=[
                AclRule(
                    action="permit",
                    source_addresses=["2001:db8::/32"],
                    provenance={"rule": provenance},
                )
            ],
        )

    with pytest.raises(ValidationError, match="prefix-list family must be ipv6"):
        PrefixListConfig(
            name="MIXED",
            family="ipv6",
            rules=[PrefixListRule(prefix="192.0.2.0/24", provenance=provenance)],
        )


def test_static_route_canonicalizes_and_requires_matching_target() -> None:
    route = StaticRouteConfig(
        family="ipv4",
        destination="192.0.2.7/24",
        next_hop="198.51.100.1",
    )

    assert route.destination == "192.0.2.0/24"

    with pytest.raises(ValidationError, match="requires a next hop"):
        StaticRouteConfig(family="ipv4", destination="192.0.2.0/24")

    with pytest.raises(ValidationError, match="next-hop family must be ipv6"):
        StaticRouteConfig(
            family="ipv6",
            destination="2001:db8::/32",
            next_hop="192.0.2.1",
        )
