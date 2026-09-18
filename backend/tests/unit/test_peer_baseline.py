"""Tests for deterministic peer-group baseline construction and evaluation."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from app.detection import (
    PeerFeature,
    PeerGroupKey,
    build_peer_baseline,
    evaluate_peer_baseline,
)
from app.domain import CanonicalConfig
from app.parsers import parse_configuration

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
DEVICE_ID = UUID("f6156954-3f3b-4aa2-b693-5a710fe35d44")


def _config(
    hostname: str,
    *,
    ssh_version: str = "2",
    vlan_id: int = 10,
    acl_source: str = "host 192.0.2.10",
    bgp_as: int = 65001,
    ospf_area: str = "0",
    route_destination: str = "0.0.0.0 0.0.0.0",
    extra: str = "",
) -> CanonicalConfig:
    text = (
        "version 17.9\n"
        f"hostname {hostname}\n"
        "aaa new-model\n"
        f"ip ssh version {ssh_version}\n"
        "snmp-server group SECURE v3 priv\n"
        "ntp server 192.0.2.10\n"
        "logging host 192.0.2.20\n"
        f"vlan {vlan_id}\n"
        " name USERS\n"
        "!\n"
        "ip access-list extended MGMT\n"
        f" 10 permit tcp {acl_source} any eq 22\n"
        " 20 deny ip any any\n"
        "!\n"
        f"ip route {route_destination} 192.0.2.1\n"
        f"router bgp {bgp_as}\n"
        " bgp router-id 192.0.2.2\n"
        " neighbor 192.0.2.1 remote-as 65002\n"
        "!\n"
        "router ospf 10\n"
        " router-id 192.0.2.2\n"
        f" network 10.0.0.0 0.0.0.255 area {ospf_area}\n"
        "!\n"
        f"{extra}"
    )
    config = parse_configuration(
        text,
        filename=f"{hostname}.cfg",
        collected_at=COLLECTED_AT,
    )
    config.device.role = "edge-router"
    config.device.site_class = "datacenter"
    config.device.service_profile = "internet-edge"
    return config


def test_peer_group_key_requires_complete_metadata() -> None:
    config = parse_configuration(
        "hostname edge\n", filename="edge.cfg", collected_at=COLLECTED_AT
    )

    with pytest.raises(ValueError, match="device_role, service_profile, site_class"):
        PeerGroupKey.from_config(config)


def test_baseline_accepts_matching_peer_without_findings() -> None:
    peers = [_config(f"edge-{index}") for index in range(1, 4)]
    baseline = build_peer_baseline(peers)

    findings = evaluate_peer_baseline(peers[0], baseline, device_id=DEVICE_ID)

    assert findings == []
    assert baseline.sample_count == 3
    assert baseline.unsupported_ratio_median == 0.0
    assert baseline.unsupported_ratio_limit == 0.05
    assert {feature.field for feature in baseline.features} == set(PeerFeature)


def test_baseline_reports_auditable_feature_and_parser_deviations() -> None:
    peers = [_config(f"edge-{index}") for index in range(1, 4)]
    baseline = build_peer_baseline(peers)
    outlier = _config(
        "edge-outlier",
        ssh_version="1",
        vlan_id=20,
        acl_source="any",
        bgp_as=65100,
        ospf_area="1",
        route_destination="203.0.113.0 255.255.255.0",
        extra="unsupported feature alpha\nunsupported feature beta\n",
    )

    first = evaluate_peer_baseline(outlier, baseline, device_id=DEVICE_ID)
    repeated = evaluate_peer_baseline(outlier, baseline, device_id=DEVICE_ID)

    assert [finding.finding_id for finding in first] == [
        finding.finding_id for finding in repeated
    ]
    assert {finding.category for finding in first} == {
        "baseline.management.ssh_version_deviation",
        "baseline.vlans.set_deviation",
        "baseline.acls.patterns_deviation",
        "baseline.bgp.local_as_deviation",
        "baseline.ospf.areas_deviation",
        "baseline.static_routes.destinations_deviation",
        "baseline.parser.unsupported_ratio_high",
    }
    assert all(finding.detector == "peer_baseline" for finding in first)
    assert all(finding.model_version == "peer-baseline-0.1.0" for finding in first)
    ssh_finding = next(
        finding
        for finding in first
        if finding.category == "baseline.management.ssh_version_deviation"
    )
    assert ssh_finding.affected_lines == [4]
    assert ssh_finding.observed == {"management.ssh_version": "1"}
    assert ssh_finding.expected["management.ssh_version"] == "2"
    parser_finding = next(
        finding
        for finding in first
        if finding.category == "baseline.parser.unsupported_ratio_high"
    )
    assert parser_finding.affected_lines == [24, 25]


def test_consensus_support_is_recorded_and_used_as_confidence() -> None:
    peers = [_config(f"edge-{index}") for index in range(1, 4)]
    outlier = _config("edge-4", ssh_version="1")
    baseline = build_peer_baseline([*peers, outlier])
    ssh_feature = next(
        feature
        for feature in baseline.features
        if feature.field is PeerFeature.SSH_VERSION
    )

    findings = evaluate_peer_baseline(outlier, baseline, device_id=DEVICE_ID)
    ssh_finding = next(
        finding
        for finding in findings
        if finding.category == "baseline.management.ssh_version_deviation"
    )

    assert ssh_feature.expected == "2"
    assert ssh_feature.support_count == 3
    assert ssh_feature.support_ratio == 0.75
    assert ssh_finding.confidence == 0.75
    assert ssh_finding.anomaly_score == 0.75


def test_baseline_rejects_too_few_or_mismatched_peers() -> None:
    first = _config("edge-1")
    second = _config("edge-2")
    second.device.site_class = "branch"

    with pytest.raises(ValueError, match="at least 3"):
        build_peer_baseline([first])
    with pytest.raises(ValueError, match="one peer group"):
        build_peer_baseline([first, second], minimum_samples=2)


def test_evaluation_rejects_wrong_peer_group() -> None:
    peers = [_config(f"edge-{index}") for index in range(1, 4)]
    baseline = build_peer_baseline(peers)
    target = _config("branch-1")
    target.device.role = "branch-router"

    with pytest.raises(ValueError, match="does not belong"):
        evaluate_peer_baseline(target, baseline, device_id=DEVICE_ID)
