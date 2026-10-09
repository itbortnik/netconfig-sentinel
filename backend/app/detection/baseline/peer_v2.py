"""Bounded explicit peer consensus with value comparisons and partial-state reporting."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_interface, ip_network
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.detection.baseline.expanded import (
    MAX_PROJECTION_BYTES,
    ExpandedField,
    ExpandedValue,
    acl_rows,
    complete_config,
    encoded_value,
    prefix_rows,
    project_expanded_facts,
    unique_locations,
    value_digest,
)
from app.detection.baseline.models import PeerGroupKey
from app.domain import CanonicalConfig, Evidence, Finding, Severity, SourceLocation

EXPANDED_PEER_NAMESPACE = UUID("fa6a84e7-a6c3-4af3-bc60-bae544715273")


class ExpandedPeerFeature(StrEnum):
    SSH_ENABLED = "management.ssh_enabled"
    SSH_VERSION = "management.ssh_version"
    TELNET_ENABLED = "management.telnet_enabled"
    AAA_ENABLED = "management.aaa_enabled"
    SNMP_VERSIONS = "management.snmp_versions"
    NTP_SERVERS = "management.ntp_servers"
    SYSLOG_SERVERS = "management.syslog_servers"
    USER_PATTERNS = "local_users.patterns"
    INTERFACE_PATTERNS = "interfaces.patterns"
    VLAN_SET = "vlans.set"
    ACL_PATTERNS = "acls.patterns"
    PREFIX_PATTERNS = "prefix_lists.patterns"
    BGP_PRESENT = "bgp.present"
    BGP_LOCAL_AS = "bgp.local_as"
    BGP_ROUTER_ID_CONFIGURED = "bgp.router_id_configured"
    BGP_NEIGHBOR_PATTERNS = "bgp.neighbor_patterns"
    OSPF_PRESENT = "ospf.present"
    OSPF_PROCESS_PATTERNS = "ospf.process_patterns"
    STATIC_TARGETS = "static_routes.targets"


_BOOLEAN_FEATURES = {
    ExpandedPeerFeature.SSH_ENABLED,
    ExpandedPeerFeature.TELNET_ENABLED,
    ExpandedPeerFeature.AAA_ENABLED,
    ExpandedPeerFeature.BGP_PRESENT,
    ExpandedPeerFeature.BGP_ROUTER_ID_CONFIGURED,
    ExpandedPeerFeature.OSPF_PRESENT,
}


class PeerSample(BaseModel):
    """Declared identities and source pins, not independent network-ownership attestations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    hostname: str = Field(min_length=1, max_length=255)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collected_at: datetime

    @model_validator(mode="after")
    def bounded_identity(self) -> PeerSample:
        if self.hostname != self.hostname.strip() or not self.hostname.isprintable():
            raise ValueError("invalid declared peer hostname")
        if self.collected_at.utcoffset() is None:
            raise ValueError("peer collection time requires a timezone")
        return self


class ExpandedConsensusFeature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    field: ExpandedPeerFeature
    expected: ExpandedValue
    support_count: int = Field(strict=True, ge=1, le=20)
    sample_count: int = Field(strict=True, ge=3, le=20)

    @model_validator(mode="after")
    def typed_consensus(self) -> ExpandedConsensusFeature:
        if self.support_count > self.sample_count:
            raise ValueError("support count exceeds the peer sample count")
        allowed: tuple[type[object], ...]
        if self.field in _BOOLEAN_FEATURES:
            allowed = (bool,)
        elif self.field is ExpandedPeerFeature.SSH_VERSION:
            allowed = (str, type(None))
        elif self.field is ExpandedPeerFeature.BGP_LOCAL_AS:
            allowed = (int, type(None))
        else:
            allowed = (tuple,)
        if type(self.expected) not in allowed:
            raise ValueError("peer feature has the wrong primitive type")
        encoded_value(self.expected)
        return self

    @property
    def support_ratio(self) -> float:
        return self.support_count / self.sample_count


class ExpandedPeerBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    model_version: Literal["peer-baseline-0.2.0"] = "peer-baseline-0.2.0"
    group: PeerGroupKey
    sample_count: int = Field(strict=True, ge=3, le=20)
    samples: tuple[PeerSample, ...] = Field(min_length=3, max_length=20)
    consensus_threshold: float = Field(gt=0.5, le=1)
    features: tuple[ExpandedConsensusFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    omitted_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    unsupported_ratio_median: float = Field(default=0.0, ge=0, le=0)
    unsupported_ratio_limit: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def bound_complete_profile(self) -> ExpandedPeerBaseline:
        if len(self.samples) != self.sample_count:
            raise ValueError("declared peer count differs from selected sources")
        if len({item.hostname.casefold() for item in self.samples}) != self.sample_count or (
            len({item.source_sha256 for item in self.samples}) != self.sample_count
        ):
            raise ValueError("peer population requires distinct hostnames and source hashes")
        if self.samples != tuple(sorted(self.samples, key=lambda item: item.source_sha256)):
            raise ValueError("peer source bindings must have canonical order")
        fields = [feature.field for feature in self.features]
        omitted = list(self.omitted_features)
        if len(fields + omitted) != len(set(fields + omitted)) or (
            set(fields + omitted) != set(ExpandedPeerFeature)
        ):
            raise ValueError("peer feature inventory must be complete, disjoint and unique")
        if fields != sorted(fields, key=lambda item: item.value) or omitted != sorted(
            omitted, key=lambda item: item.value
        ):
            raise ValueError("peer features must have canonical order")
        if any(
            item.sample_count != self.sample_count or item.support_ratio < self.consensus_threshold
            for item in self.features
        ):
            raise ValueError("every feature must match the sample count and consensus threshold")
        if len(self.model_dump_json().encode("utf-8")) > MAX_PROJECTION_BYTES:
            raise ValueError("expanded peer profile exceeds its byte limit")
        return self

    def fingerprint(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def _features(
    config: CanonicalConfig,
) -> tuple[
    dict[ExpandedPeerFeature, ExpandedValue], dict[ExpandedPeerFeature, tuple[SourceLocation, ...]]
]:
    facts = project_expanded_facts(config)  # Complete parsing, duplicate identities and size gates.
    values: dict[ExpandedPeerFeature, ExpandedValue] = {}
    locations: dict[ExpandedPeerFeature, tuple[SourceLocation, ...]] = {}

    def update_source(value: str | None) -> object:
        if value is None:
            return None
        try:
            address = ip_address(value)
        except ValueError:
            return ["interface", value]
        return ["address", address.version]

    def add(feature: ExpandedPeerFeature, value: ExpandedValue, fields: set[ExpandedField]) -> None:
        encoded_value(value)
        values[feature] = value
        locations[feature] = unique_locations(
            [loc for fact in facts if fact.field in fields for loc in fact.locations]
        )

    for feature in (
        ExpandedPeerFeature.SSH_ENABLED,
        ExpandedPeerFeature.SSH_VERSION,
        ExpandedPeerFeature.TELNET_ENABLED,
        ExpandedPeerFeature.AAA_ENABLED,
        ExpandedPeerFeature.SNMP_VERSIONS,
        ExpandedPeerFeature.NTP_SERVERS,
        ExpandedPeerFeature.SYSLOG_SERVERS,
        ExpandedPeerFeature.VLAN_SET,
        ExpandedPeerFeature.BGP_PRESENT,
        ExpandedPeerFeature.OSPF_PRESENT,
    ):
        field = ExpandedField(feature.value)
        add(feature, next(fact.value for fact in facts if fact.field is field), {field})
    add(
        ExpandedPeerFeature.USER_PATTERNS,
        tuple(
            sorted(
                encoded_value(
                    [
                        user.privilege,
                        user.login_class,
                        sorted([item.kind, item.encoding] for item in user.authentication),
                    ]
                )
                for user in config.local_users
            )
        ),
        {field for field in ExpandedField if field.value.startswith("local_user.")},
    )
    add(
        ExpandedPeerFeature.INTERFACE_PATTERNS,
        tuple(
            sorted(
                encoded_value(
                    [
                        interface.enabled,
                        interface.switchport_mode,
                        None
                        if interface.access_vlan is None
                        else [interface.access_vlan.vlan_id, interface.access_vlan.name],
                        None
                        if interface.native_vlan is None
                        else [interface.native_vlan.vlan_id, interface.native_vlan.name],
                        None
                        if interface.allowed_vlans is None
                        else [
                            interface.allowed_vlans.all_vlans,
                            interface.allowed_vlans.vlan_ids,
                            sorted(interface.allowed_vlans.vlan_names),
                        ],
                        sorted(
                            [
                                [family, ip_interface(address).network.prefixlen]
                                for family, address in sorted(
                                    {(item.family, item.address) for item in interface.addresses}
                                )
                            ]
                        ),
                    ]
                )
                for interface in config.interfaces
            )
        ),
        {field for field in ExpandedField if field.value.startswith("interface.")},
    )
    add(
        ExpandedPeerFeature.ACL_PATTERNS,
        tuple(
            sorted(
                encoded_value([acl.family, acl.kind, acl_rows(acl, include_labels=False)])
                for acl in config.acls
            )
        ),
        {ExpandedField.ACL_PRESENT, ExpandedField.ACL_RULES},
    )
    add(
        ExpandedPeerFeature.PREFIX_PATTERNS,
        tuple(
            sorted(
                encoded_value([prefix.family, prefix_rows(prefix, include_labels=False)])
                for prefix in config.prefix_lists
            )
        ),
        {ExpandedField.PREFIX_PRESENT, ExpandedField.PREFIX_RULES},
    )
    bgp = config.bgp
    add(
        ExpandedPeerFeature.BGP_LOCAL_AS,
        None if bgp is None else bgp.local_as,
        {ExpandedField.BGP_LOCAL_AS},
    )
    add(
        ExpandedPeerFeature.BGP_ROUTER_ID_CONFIGURED,
        bgp is not None and bgp.router_id is not None,
        {ExpandedField.BGP_ROUTER_ID},
    )
    add(
        ExpandedPeerFeature.BGP_NEIGHBOR_PATTERNS,
        ()
        if bgp is None
        else tuple(
            sorted(
                encoded_value(
                    [
                        neighbor.family,
                        neighbor.remote_as,
                        neighbor.session_type,
                        update_source(neighbor.update_source),
                        neighbor.enabled,
                    ]
                )
                for neighbor in bgp.neighbors
            )
        ),
        {field for field in ExpandedField if field.value.startswith("bgp.neighbor.")},
    )
    add(
        ExpandedPeerFeature.OSPF_PROCESS_PATTERNS,
        tuple(
            sorted(
                encoded_value(
                    [
                        process.version,
                        process.router_id is not None,
                        process.passive_default,
                        sorted(
                            [
                                [ip_network(network.prefix).prefixlen, network.area_id]
                                for network in process.networks
                            ]
                        ),
                        sorted(
                            encoded_value([interface.area_id, interface.passive, interface.cost])
                            for interface in process.interfaces
                        ),
                    ]
                )
                for process in config.ospf
            )
        ),
        {field for field in ExpandedField if field.value.startswith("ospf.")},
    )
    add(
        ExpandedPeerFeature.STATIC_TARGETS,
        tuple(
            sorted(
                {
                    encoded_value(
                        [
                            route.family,
                            route.destination,
                            route.next_hop,
                            route.outgoing_interface,
                            route.preference,
                            route.discard,
                        ]
                    )
                    for route in config.static_routes
                }
            )
        ),
        {ExpandedField.STATIC_TARGETS},
    )
    return values, locations


def build_expanded_peer_baseline(
    configs: Sequence[CanonicalConfig],
    *,
    consensus_threshold: float = 0.75,
    unsupported_ratio_tolerance: float = 0.05,
) -> ExpandedPeerBaseline:
    if not 3 <= len(configs) <= 20:
        raise ValueError("expanded peer baseline requires 3 to 20 configurations")
    if not 0.5 < consensus_threshold <= 1 or not 0 <= unsupported_ratio_tolerance <= 1:
        raise ValueError("invalid finite peer thresholds")
    configs = [complete_config(config) for config in configs]
    group = PeerGroupKey.from_config(configs[0])
    if any(PeerGroupKey.from_config(config) != group for config in configs):
        raise ValueError("all configurations must belong to one peer group")
    samples = tuple(
        sorted(
            (
                PeerSample(
                    hostname=config.device.hostname or "",
                    source_sha256=config.source.sha256,
                    collected_at=config.source.collected_at,
                )
                for config in configs
            ),
            key=lambda item: item.source_sha256,
        )
    )
    # Validate identities before computing a profile; copies of a source cannot supply votes.
    if len({item.hostname.casefold() for item in samples}) != len(samples) or (
        len({item.source_sha256 for item in samples}) != len(samples)
    ):
        raise ValueError("peer population requires distinct hostnames and source hashes")
    extracted = [_features(config)[0] for config in configs]
    features = []
    omitted = []
    for feature in sorted(ExpandedPeerFeature, key=lambda item: item.value):
        counts = Counter(row[feature] for row in extracted)
        expected, support = max(counts.items(), key=lambda item: (item[1], encoded_value(item[0])))
        if support / len(configs) >= consensus_threshold:
            features.append(
                ExpandedConsensusFeature(
                    field=feature,
                    expected=expected,
                    support_count=support,
                    sample_count=len(configs),
                )
            )
        else:
            omitted.append(feature)
    return ExpandedPeerBaseline(
        group=group,
        sample_count=len(configs),
        samples=samples,
        consensus_threshold=consensus_threshold,
        features=tuple(features),
        omitted_features=tuple(omitted),
        unsupported_ratio_limit=unsupported_ratio_tolerance,
    )


class ExpandedPeerEvaluation(BaseModel):
    """An empty partial result is not misrepresented as a completed comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["peer-comparison-report-0.2.0"] = "peer-comparison-report-0.2.0"
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["completed", "partial"]
    unsupported_ratio: float = Field(ge=0, le=1)
    profile_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    compared_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    skipped_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    findings: tuple[Finding, ...] = Field(max_length=len(ExpandedPeerFeature) + 1)
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def bound_status_and_findings(self) -> ExpandedPeerEvaluation:
        if len(self.profile_features) != len(set(self.profile_features)) or (
            self.profile_features
            != tuple(sorted(self.profile_features, key=lambda item: item.value))
        ):
            raise ValueError("invalid evaluation feature inventory")
        if self.status == "completed":
            if (
                self.skipped_features
                or self.compared_features != self.profile_features
                or self.unsupported_ratio != 0
            ):
                raise ValueError(
                    "completed comparison requires all selected features and complete parsing"
                )
        elif self.compared_features or self.skipped_features != self.profile_features:
            raise ValueError("partial comparison must skip every property feature")
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError("duplicate peer findings")
        for finding in self.findings:
            if (
                finding.device_id != self.device_id
                or finding.model_version != "peer-baseline-0.2.0"
                or (
                    finding.detector != "peer_baseline"
                    or finding.observed.get("source_sha256") != self.source_sha256
                    or finding.expected.get("baseline_sha256") != self.baseline_sha256
                )
            ):
                raise ValueError("peer finding is not bound to this evaluation")
            if (
                self.status == "partial"
                and finding.category != "baseline.parser.unsupported_ratio_high"
            ):
                raise ValueError("partial comparison cannot claim a property difference")
        return self


def _finding(
    config: CanonicalConfig,
    baseline: ExpandedPeerBaseline,
    *,
    device_id: UUID,
    category: str,
    actual: object,
    expected: dict[str, object],
    score: float,
    confidence: float,
    locations: tuple[SourceLocation, ...],
    message: str,
) -> Finding:
    digest = baseline.fingerprint()
    identity = encoded_value(
        [
            str(device_id),
            baseline.model_version,
            digest,
            config.source.sha256,
            category,
            value_digest(actual),
        ]
    )
    limitations = [
        "Exact peer consensus is not an approved security baseline "
        "or proof of incorrect network behavior.",
        "Support and deviation scores are not calibrated fault probabilities; "
        "MEDIUM is a review priority.",
        "Declared hostnames, source hashes and inventory labels "
        "do not independently verify device or network identity.",
        "Unsupported commands, effective vendor defaults and credential values "
        "are outside property comparison.",
        "No network simulation, ML evaluation or device change was run.",
    ]
    if not locations:
        limitations.append(
            "No current source anchor exists for this absent or unavailable supported feature."
        )
    return Finding(
        finding_id=uuid5(EXPANDED_PEER_NAMESPACE, identity),
        device_id=device_id,
        detector="peer_baseline",
        category=category,
        title=f"Expanded peer deviation: {category}",
        severity=Severity.MEDIUM,
        confidence=confidence,
        anomaly_score=score,
        affected_lines=sorted({line for loc in locations for line in loc.source_lines}),
        evidence=[
            Evidence(kind="peer_group_difference", message=message, source_location=loc)
            for loc in locations
        ]
        or [Evidence(kind="peer_group_difference", message=message)],
        observed={"value": actual, "source_sha256": config.source.sha256},
        expected={**expected, "baseline_sha256": digest},
        remediation="Review the explicit peer sources and intended network design "
        "before taking action.",
        references=["docs/expanded-comparisons.md#peer-templates"],
        limitations=limitations,
        model_version=baseline.model_version,
    )


def evaluate_expanded_peer_baseline(
    config: CanonicalConfig,
    baseline: ExpandedPeerBaseline,
    *,
    device_id: UUID,
) -> ExpandedPeerEvaluation:
    config = CanonicalConfig.model_validate(config.model_dump())
    baseline = ExpandedPeerBaseline.model_validate(baseline.model_dump())
    if PeerGroupKey.from_config(config) != baseline.group:
        raise ValueError("configuration does not belong to the selected peer group")
    if not config.device.hostname or any(
        config.device.hostname.casefold() == sample.hostname.casefold()
        or config.source.sha256 == sample.source_sha256
        for sample in baseline.samples
    ):
        raise ValueError(
            "target is missing its hostname or belongs to the selected peer population"
        )
    if config.source.collected_at.utcoffset() is None:
        raise ValueError("target collection time requires a timezone")
    if any(sample.collected_at > config.source.collected_at for sample in baseline.samples):
        raise ValueError("peer population contains future source collections")
    complete = (
        not config.parse_warnings
        and not config.unparsed_fragments
        and config.parser_confidence == 1
    )
    fields = tuple(feature.field for feature in baseline.features)
    findings: list[Finding] = []
    if complete:
        actual, locations = _features(config)
        for feature in baseline.features:
            if encoded_value(actual[feature.field]) != encoded_value(feature.expected):
                findings.append(
                    _finding(
                        config,
                        baseline,
                        device_id=device_id,
                        category=f"baseline.{feature.field.value}_deviation",
                        actual=actual[feature.field],
                        expected={
                            "value": feature.expected,
                            "peer_support_count": feature.support_count,
                            "peer_sample_count": feature.sample_count,
                            "feature": feature.field.value,
                        },
                        score=feature.support_ratio,
                        confidence=feature.support_ratio,
                        locations=locations[feature.field],
                        message=(
                            f"Supported normalized value differs from {feature.support_count} "
                            f"of {feature.sample_count} selected peers."
                        ),
                    )
                )
    ratio = 1.0 - config.parser_confidence
    if ratio > baseline.unsupported_ratio_limit:
        findings.append(
            _finding(
                config,
                baseline,
                device_id=device_id,
                category="baseline.parser.unsupported_ratio_high",
                actual=ratio,
                expected={
                    "maximum_unsupported_ratio": baseline.unsupported_ratio_limit,
                    "peer_median": baseline.unsupported_ratio_median,
                },
                score=min(
                    1.0,
                    (ratio - baseline.unsupported_ratio_limit)
                    / max(1.0 - baseline.unsupported_ratio_limit, 0.01),
                ),
                confidence=1.0,
                locations=unique_locations([item.location for item in config.unparsed_fragments]),
                message="The parser-confidence deficit exceeds the explicit limit "
                "derived from completely parsed peers.",
            )
        )
    return ExpandedPeerEvaluation(
        device_id=device_id,
        source_sha256=config.source.sha256,
        baseline_sha256=baseline.fingerprint(),
        status="completed" if complete else "partial",
        unsupported_ratio=ratio,
        profile_features=fields,
        compared_features=fields if complete else (),
        skipped_features=() if complete else fields,
        findings=tuple(findings),
        limitations=(
            "Only the exact selected, completely parsed sources supply consensus votes; "
            "no automatic peer refresh occurs.",
            "Peer templates omit individual router IDs, interface addresses and object labels; "
            "reference comparison retains them.",
            "The unsupported ratio is a parser-confidence deficit proxy, "
            "not a count of all possible vendor commands.",
            "Empty findings do not establish compliance, reachability or safety.",
            *(
                ()
                if complete
                else (
                    "Parsing is incomplete: all property comparisons were skipped; "
                    "missing values are not treated as absences.",
                )
            ),
        ),
    )
