"""Build and evaluate auditable peer-group configuration baselines."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from ipaddress import ip_network
from statistics import median
from uuid import UUID, uuid5

from app.detection.baseline.models import (
    ConsensusFeature,
    FeatureValue,
    PeerBaseline,
    PeerFeature,
    PeerGroupKey,
)
from app.domain import (
    AclConfig,
    CanonicalConfig,
    Evidence,
    Finding,
    Severity,
    SourceLocation,
    VlanConfig,
)

PEER_BASELINE_NAMESPACE = UUID("63db00fc-8fc5-4812-8af0-ae1f87b8e6fc")

_SEVERITIES = {
    PeerFeature.SSH_ENABLED: Severity.HIGH,
    PeerFeature.SSH_VERSION: Severity.HIGH,
    PeerFeature.TELNET_ENABLED: Severity.HIGH,
    PeerFeature.AAA_ENABLED: Severity.HIGH,
    PeerFeature.SNMP_VERSIONS: Severity.HIGH,
    PeerFeature.NTP_CONFIGURED: Severity.MEDIUM,
    PeerFeature.SYSLOG_CONFIGURED: Severity.HIGH,
    PeerFeature.VLAN_SET: Severity.HIGH,
    PeerFeature.ACL_PATTERNS: Severity.HIGH,
    PeerFeature.BGP_PRESENT: Severity.HIGH,
    PeerFeature.BGP_LOCAL_AS: Severity.HIGH,
    PeerFeature.OSPF_PRESENT: Severity.MEDIUM,
    PeerFeature.OSPF_AREAS: Severity.HIGH,
    PeerFeature.STATIC_ROUTE_DESTINATIONS: Severity.HIGH,
}

_REMEDIATIONS = {
    PeerFeature.SSH_ENABLED: "Align SSH enablement with the approved peer template.",
    PeerFeature.SSH_VERSION: "Align the SSH protocol version with the peer baseline.",
    PeerFeature.TELNET_ENABLED: "Align Telnet state with the approved peer template.",
    PeerFeature.AAA_ENABLED: "Align centralized AAA with the approved peer template.",
    PeerFeature.SNMP_VERSIONS: "Align SNMP versions with the approved peer template.",
    PeerFeature.NTP_CONFIGURED: "Restore the expected NTP configuration.",
    PeerFeature.SYSLOG_CONFIGURED: "Restore the expected remote logging configuration.",
    PeerFeature.VLAN_SET: "Review the VLAN inventory and align it with comparable devices.",
    PeerFeature.ACL_PATTERNS: "Review ACL intent and align the rule pattern with approved peers.",
    PeerFeature.BGP_PRESENT: "Review whether BGP should be configured for this peer group.",
    PeerFeature.BGP_LOCAL_AS: "Verify the intended local AS against the site routing design.",
    PeerFeature.OSPF_PRESENT: "Review whether OSPF should be configured for this peer group.",
    PeerFeature.OSPF_AREAS: "Align OSPF area membership with the site routing design.",
    PeerFeature.STATIC_ROUTE_DESTINATIONS: (
        "Review missing or unexpected static-route destinations against the routing design."
    ),
}


def build_peer_baseline(
    configs: Sequence[CanonicalConfig],
    *,
    minimum_samples: int = 3,
    consensus_threshold: float = 0.75,
    unsupported_ratio_tolerance: float = 0.05,
) -> PeerBaseline:
    """Build an exact-consensus profile from explicitly selected comparable peers."""

    if minimum_samples < 2:
        raise ValueError("minimum_samples must be at least 2")
    if len(configs) < minimum_samples:
        raise ValueError(
            f"peer baseline requires at least {minimum_samples} configurations"
        )
    if not 0.5 < consensus_threshold <= 1.0:
        raise ValueError("consensus_threshold must be greater than 0.5 and at most 1.0")
    if not 0.0 <= unsupported_ratio_tolerance <= 1.0:
        raise ValueError("unsupported_ratio_tolerance must be between 0 and 1")

    group = PeerGroupKey.from_config(configs[0])
    for config in configs[1:]:
        if PeerGroupKey.from_config(config) != group:
            raise ValueError("all baseline configurations must belong to one peer group")

    extracted = [_extract_features(config) for config in configs]
    features: list[ConsensusFeature] = []
    for field in PeerFeature:
        counts = Counter(row[field] for row in extracted)
        expected, support_count = max(
            counts.items(), key=lambda item: (item[1], repr(item[0]))
        )
        if support_count / len(configs) >= consensus_threshold:
            features.append(
                ConsensusFeature(
                    field=field,
                    expected=expected,
                    support_count=support_count,
                    sample_count=len(configs),
                )
            )

    unsupported_ratios = [1.0 - config.parser_confidence for config in configs]
    ratio_median = float(median(unsupported_ratios))
    ratio_limit = min(1.0, ratio_median + unsupported_ratio_tolerance)
    return PeerBaseline(
        group=group,
        sample_count=len(configs),
        consensus_threshold=consensus_threshold,
        features=tuple(features),
        unsupported_ratio_median=ratio_median,
        unsupported_ratio_limit=ratio_limit,
    )


def evaluate_peer_baseline(
    config: CanonicalConfig,
    baseline: PeerBaseline,
    *,
    device_id: UUID,
) -> list[Finding]:
    """Return deterministic findings for deviations from a matching baseline."""

    if PeerGroupKey.from_config(config) != baseline.group:
        raise ValueError("configuration does not belong to the baseline peer group")

    actual = _extract_features(config)
    findings = [
        _feature_finding(config, baseline, feature, actual[feature.field], device_id)
        for feature in baseline.features
        if actual[feature.field] != feature.expected
    ]
    unsupported_ratio = 1.0 - config.parser_confidence
    if unsupported_ratio > baseline.unsupported_ratio_limit:
        findings.append(
            _unsupported_ratio_finding(
                config, baseline, unsupported_ratio, device_id
            )
        )
    return findings


def _extract_features(config: CanonicalConfig) -> dict[PeerFeature, FeatureValue]:
    ospf_areas = {
        network.area_id for process in config.ospf for network in process.networks
    }
    ospf_areas.update(
        interface.area_id
        for process in config.ospf
        for interface in process.interfaces
        if interface.area_id is not None
    )
    return {
        PeerFeature.SSH_ENABLED: config.management.ssh_enabled,
        PeerFeature.SSH_VERSION: config.management.ssh_version,
        PeerFeature.TELNET_ENABLED: config.management.telnet_enabled,
        PeerFeature.AAA_ENABLED: config.management.aaa_enabled,
        PeerFeature.SNMP_VERSIONS: tuple(config.management.snmp_versions),
        PeerFeature.NTP_CONFIGURED: bool(config.management.ntp_servers),
        PeerFeature.SYSLOG_CONFIGURED: bool(config.management.syslog_servers),
        PeerFeature.VLAN_SET: tuple(sorted(_vlan_key(vlan) for vlan in config.vlans)),
        PeerFeature.ACL_PATTERNS: tuple(sorted(_acl_pattern(acl) for acl in config.acls)),
        PeerFeature.BGP_PRESENT: config.bgp is not None,
        PeerFeature.BGP_LOCAL_AS: None if config.bgp is None else config.bgp.local_as,
        PeerFeature.OSPF_PRESENT: bool(config.ospf),
        PeerFeature.OSPF_AREAS: tuple(sorted(ospf_areas, key=_network_sort_key)),
        PeerFeature.STATIC_ROUTE_DESTINATIONS: tuple(
            sorted(
                (route.destination for route in config.static_routes),
                key=_network_sort_key,
            )
        ),
    }


def _vlan_key(vlan: VlanConfig) -> str:
    return f"{vlan.vlan_id if vlan.vlan_id is not None else '-'}:{vlan.name or '-'}"


def _acl_pattern(acl: AclConfig) -> str:
    rule_patterns = []
    for rule in acl.rules:
        rule_patterns.append(
            "|".join(
                (
                    rule.action,
                    rule.protocol or "*",
                    f"src={','.join(rule.source_addresses) or '*'}",
                    f"dst={','.join(rule.destination_addresses) or '*'}",
                    f"sport={','.join(rule.source_ports) or '*'}",
                    f"dport={','.join(rule.destination_ports) or '*'}",
                )
            )
        )
    return f"{acl.family}:{acl.kind}:" + ">".join(rule_patterns)


def _network_sort_key(value: str) -> tuple[int, int, int]:
    try:
        network = ip_network(value, strict=False)
    except ValueError:
        return (3, 0, 0)
    return (network.version, int(network.network_address), network.prefixlen)


def _feature_finding(
    config: CanonicalConfig,
    baseline: PeerBaseline,
    feature: ConsensusFeature,
    actual: FeatureValue,
    device_id: UUID,
) -> Finding:
    locations = _feature_locations(config, feature.field)
    affected_lines = _affected_lines(locations)
    category = f"baseline.{feature.field.value}_deviation"
    evidence = [
        Evidence(
            kind="peer_group_difference",
            message=(
                f"The normalized value differs from {feature.support_count} of "
                f"{feature.sample_count} comparable devices."
            ),
            source_location=location,
        )
        for location in locations
    ]
    limitations: list[str] = []
    if not evidence:
        evidence.append(
            Evidence(
                kind="peer_group_difference",
                message=(
                    f"The normalized value differs from {feature.support_count} of "
                    f"{feature.sample_count} comparable devices."
                ),
            )
        )
        limitations.append(
            "No explicit source location exists because the deviation is an absent "
            "supported feature."
        )
    return Finding(
        finding_id=_finding_id(device_id, baseline.group, category, affected_lines),
        device_id=device_id,
        detector="peer_baseline",
        category=category,
        title=f"Peer baseline deviation: {feature.field.value}",
        severity=_SEVERITIES[feature.field],
        confidence=min(config.parser_confidence, feature.support_ratio),
        anomaly_score=feature.support_ratio,
        affected_lines=affected_lines,
        evidence=evidence,
        observed={feature.field.value: actual},
        expected={
            feature.field.value: feature.expected,
            "peer_support_count": feature.support_count,
            "peer_sample_count": feature.sample_count,
        },
        remediation=_REMEDIATIONS[feature.field],
        references=("docs/baseline.md#exact-consensus-features",),
        limitations=limitations,
        model_version=baseline.model_version,
    )


def _unsupported_ratio_finding(
    config: CanonicalConfig,
    baseline: PeerBaseline,
    actual: float,
    device_id: UUID,
) -> Finding:
    locations = _unique_locations(
        [fragment.location for fragment in config.unparsed_fragments]
    )
    affected_lines = _affected_lines(locations)
    category = "baseline.parser.unsupported_ratio_high"
    denominator = max(1.0 - baseline.unsupported_ratio_limit, 0.01)
    anomaly_score = min(1.0, (actual - baseline.unsupported_ratio_limit) / denominator)
    evidence = [
        Evidence(
            kind="peer_group_difference",
            message="The unsupported-line ratio exceeds the peer-derived limit.",
            source_location=location,
        )
        for location in locations
    ]
    if not evidence:
        evidence.append(
            Evidence(
                kind="peer_group_difference",
                message="The unsupported-line ratio exceeds the peer-derived limit.",
            )
        )
    return Finding(
        finding_id=_finding_id(device_id, baseline.group, category, affected_lines),
        device_id=device_id,
        detector="peer_baseline",
        category=category,
        title="Unsupported configuration ratio exceeds the peer baseline",
        severity=Severity.MEDIUM,
        confidence=1.0,
        anomaly_score=anomaly_score,
        affected_lines=affected_lines,
        evidence=evidence,
        observed={"unsupported_ratio": actual},
        expected={
            "maximum_unsupported_ratio": baseline.unsupported_ratio_limit,
            "peer_median": baseline.unsupported_ratio_median,
        },
        remediation=(
            "Review unsupported statements and extend parsing only for documented syntax."
        ),
        references=("docs/baseline.md#unsupported-syntax-ratio",),
        model_version=baseline.model_version,
    )


def _feature_locations(
    config: CanonicalConfig, field: PeerFeature
) -> tuple[SourceLocation, ...]:
    management_keys = {
        PeerFeature.SSH_ENABLED: "ssh_enabled",
        PeerFeature.SSH_VERSION: "ssh_version",
        PeerFeature.TELNET_ENABLED: "telnet_enabled",
        PeerFeature.AAA_ENABLED: "aaa_enabled",
        PeerFeature.SNMP_VERSIONS: "snmp_versions",
        PeerFeature.NTP_CONFIGURED: "ntp_servers",
        PeerFeature.SYSLOG_CONFIGURED: "syslog_servers",
    }
    if field in management_keys:
        location = config.management.provenance.get(management_keys[field])
        return () if location is None else (location,)
    if field is PeerFeature.VLAN_SET:
        return _unique_locations(
            [location for vlan in config.vlans for location in vlan.provenance.values()]
        )
    if field is PeerFeature.ACL_PATTERNS:
        return _unique_locations(
            [
                location
                for acl in config.acls
                for location in (
                    list(acl.provenance.values())
                    + [
                        item
                        for rule in acl.rules
                        for item in rule.provenance.values()
                    ]
                )
            ]
        )
    if field in {PeerFeature.BGP_PRESENT, PeerFeature.BGP_LOCAL_AS}:
        if config.bgp is None:
            return ()
        return _unique_locations(list(config.bgp.provenance.values()))
    if field in {PeerFeature.OSPF_PRESENT, PeerFeature.OSPF_AREAS}:
        return _unique_locations(
            [
                location
                for process in config.ospf
                for location in (
                    list(process.provenance.values())
                    + [network.provenance for network in process.networks]
                    + [
                        item
                        for interface in process.interfaces
                        for item in interface.provenance.values()
                    ]
                )
            ]
        )
    if field is PeerFeature.STATIC_ROUTE_DESTINATIONS:
        return _unique_locations(
            [
                route.provenance["destination"]
                for route in config.static_routes
                if "destination" in route.provenance
            ]
        )
    return ()


def _unique_locations(
    candidates: list[SourceLocation],
) -> tuple[SourceLocation, ...]:
    locations: list[SourceLocation] = []
    seen: set[tuple[tuple[int, ...], str]] = set()
    for location in sorted(candidates, key=lambda item: item.source_lines[0]):
        key = (tuple(location.source_lines), location.raw_text_hash)
        if key not in seen:
            locations.append(location)
            seen.add(key)
    return tuple(locations)


def _affected_lines(locations: tuple[SourceLocation, ...]) -> list[int]:
    return sorted({line for location in locations for line in location.source_lines})


def _finding_id(
    device_id: UUID,
    group: PeerGroupKey,
    category: str,
    affected_lines: list[int],
) -> UUID:
    group_key = "|".join(
        (
            group.vendor.value,
            group.platform,
            group.device_role,
            group.site_class,
            group.service_profile,
        )
    )
    line_key = ",".join(str(line) for line in affected_lines)
    return uuid5(
        PEER_BASELINE_NAMESPACE,
        f"{device_id}:{group_key}:{category}:{line_key}",
    )
