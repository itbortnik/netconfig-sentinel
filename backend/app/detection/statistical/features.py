"""Stable structured feature extraction for statistical detectors."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator

from app.domain import CanonicalConfig, SourceLocation

FEATURE_SCHEMA_VERSION = "structured-features-0.1.0"

FEATURE_NAMES = (
    "management.ssh_enabled",
    "management.ssh_v1",
    "management.telnet_enabled",
    "management.aaa_enabled",
    "management.snmp_legacy",
    "management.snmp_v3",
    "management.ntp_server_count",
    "management.syslog_server_count",
    "interfaces.count",
    "interfaces.disabled_count",
    "interfaces.ipv4_address_count",
    "interfaces.ipv6_address_count",
    "interfaces.access_count",
    "interfaces.trunk_count",
    "vlans.count",
    "acls.count",
    "acls.rule_count",
    "acls.permit_ratio",
    "prefix_lists.count",
    "prefix_lists.rule_count",
    "static_routes.count",
    "static_routes.discard_count",
    "static_routes.default_count",
    "bgp.present",
    "bgp.neighbor_count",
    "bgp.external_neighbor_count",
    "bgp.disabled_neighbor_count",
    "ospf.process_count",
    "ospf.area_count",
    "ospf.passive_interface_count",
    "parser.unsupported_ratio",
    "parser.warning_count",
    "parser.unparsed_fragment_count",
)


class StructuredFeatureVector(BaseModel):
    """One ordered vector plus source locations usable for diagnostics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = FEATURE_SCHEMA_VERSION
    names: tuple[str, ...] = FEATURE_NAMES
    values: tuple[float, ...]
    locations: dict[str, tuple[SourceLocation, ...]]

    @model_validator(mode="after")
    def dimensions_must_match_schema(self) -> StructuredFeatureVector:
        if self.names != FEATURE_NAMES:
            raise ValueError("feature names do not match the supported schema")
        if len(self.values) != len(self.names):
            raise ValueError("feature value count must match feature names")
        if any(name not in self.names for name in self.locations):
            raise ValueError("feature locations contain an unknown feature name")
        return self

    def as_row(self) -> list[float]:
        return list(self.values)

    def as_dict(self) -> dict[str, float]:
        return dict(zip(self.names, self.values, strict=True))


def extract_structured_features(config: CanonicalConfig) -> StructuredFeatureVector:
    """Extract a deterministic, vendor-neutral numeric feature vector."""

    interfaces = config.interfaces
    acl_rules = [rule for acl in config.acls for rule in acl.rules]
    ospf_areas = {
        network.area_id for process in config.ospf for network in process.networks
    }
    ospf_areas.update(
        interface.area_id
        for process in config.ospf
        for interface in process.interfaces
        if interface.area_id is not None
    )
    bgp_neighbors = [] if config.bgp is None else config.bgp.neighbors
    permit_count = sum(rule.action == "permit" for rule in acl_rules)
    values = (
        _flag(config.management.ssh_enabled),
        _flag(config.management.ssh_version == "1"),
        _flag(config.management.telnet_enabled),
        _flag(config.management.aaa_enabled),
        _flag(bool({"v1", "v2c"}.intersection(config.management.snmp_versions))),
        _flag("v3" in config.management.snmp_versions),
        float(len(config.management.ntp_servers)),
        float(len(config.management.syslog_servers)),
        float(len(interfaces)),
        float(sum(interface.enabled is False for interface in interfaces)),
        float(
            sum(
                address.family == "ipv4"
                for interface in interfaces
                for address in interface.addresses
            )
        ),
        float(
            sum(
                address.family == "ipv6"
                for interface in interfaces
                for address in interface.addresses
            )
        ),
        float(sum(interface.switchport_mode == "access" for interface in interfaces)),
        float(sum(interface.switchport_mode == "trunk" for interface in interfaces)),
        float(len(config.vlans)),
        float(len(config.acls)),
        float(len(acl_rules)),
        0.0 if not acl_rules else permit_count / len(acl_rules),
        float(len(config.prefix_lists)),
        float(sum(len(prefix_list.rules) for prefix_list in config.prefix_lists)),
        float(len(config.static_routes)),
        float(sum(route.discard for route in config.static_routes)),
        float(
            sum(
                route.destination in {"0.0.0.0/0", "::/0"}
                for route in config.static_routes
            )
        ),
        _flag(config.bgp is not None),
        float(len(bgp_neighbors)),
        float(sum(neighbor.session_type == "external" for neighbor in bgp_neighbors)),
        float(sum(neighbor.enabled is False for neighbor in bgp_neighbors)),
        float(len(config.ospf)),
        float(len(ospf_areas)),
        float(
            sum(
                interface.passive is True
                for process in config.ospf
                for interface in process.interfaces
            )
        ),
        1.0 - config.parser_confidence,
        float(len(config.parse_warnings)),
        float(len(config.unparsed_fragments)),
    )
    return StructuredFeatureVector(
        values=values,
        locations=_feature_locations(config),
    )


def _flag(value: bool) -> float:
    return 1.0 if value else 0.0


def _feature_locations(
    config: CanonicalConfig,
) -> dict[str, tuple[SourceLocation, ...]]:
    result: dict[str, tuple[SourceLocation, ...]] = {}
    management = {
        "management.ssh_enabled": "ssh_enabled",
        "management.ssh_v1": "ssh_version",
        "management.telnet_enabled": "telnet_enabled",
        "management.aaa_enabled": "aaa_enabled",
        "management.snmp_legacy": "snmp_versions",
        "management.snmp_v3": "snmp_versions",
        "management.ntp_server_count": "ntp_servers",
        "management.syslog_server_count": "syslog_servers",
    }
    for feature_name, provenance_key in management.items():
        location = config.management.provenance.get(provenance_key)
        if location is not None:
            result[feature_name] = (location,)

    interface_locations = _unique_locations(
        [
            location
            for interface in config.interfaces
            for location in (
                list(interface.provenance.values())
                + [address.provenance for address in interface.addresses]
            )
        ]
    )
    for name in FEATURE_NAMES[8:14]:
        result[name] = interface_locations
    result["vlans.count"] = _unique_locations(
        [location for vlan in config.vlans for location in vlan.provenance.values()]
    )

    acl_locations = _unique_locations(
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
    for name in FEATURE_NAMES[15:18]:
        result[name] = acl_locations

    prefix_locations = _unique_locations(
        [
            location
            for prefix_list in config.prefix_lists
            for location in (
                list(prefix_list.provenance.values())
                + [rule.provenance for rule in prefix_list.rules]
            )
        ]
    )
    for name in FEATURE_NAMES[18:20]:
        result[name] = prefix_locations

    route_locations = _unique_locations(
        [
            location
            for route in config.static_routes
            for location in route.provenance.values()
        ]
    )
    for name in FEATURE_NAMES[20:23]:
        result[name] = route_locations

    bgp_locations = (
        ()
        if config.bgp is None
        else _unique_locations(
            list(config.bgp.provenance.values())
            + [
                location
                for neighbor in config.bgp.neighbors
                for location in neighbor.provenance.values()
            ]
        )
    )
    for name in FEATURE_NAMES[23:27]:
        result[name] = bgp_locations

    ospf_locations = _unique_locations(
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
    for name in FEATURE_NAMES[27:30]:
        result[name] = ospf_locations

    unparsed_locations = _unique_locations(
        [fragment.location for fragment in config.unparsed_fragments]
    )
    for name in FEATURE_NAMES[30:33]:
        result[name] = unparsed_locations
    return result


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
