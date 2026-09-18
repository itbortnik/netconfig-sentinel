"""Deterministic execution of declarative configuration policies."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_interface, ip_network
from uuid import UUID, uuid5

from app.domain import (
    AclConfig,
    AclRule,
    CanonicalConfig,
    Evidence,
    Finding,
    InterfaceConfig,
    SourceLocation,
    Vendor,
)
from app.policies import (
    POLICY_CATALOG_VERSION,
    POLICY_RULES,
    AclField,
    Layer2Field,
    ManagementField,
    PolicyOperator,
    PolicyPlatform,
    PolicyRule,
    RoutingField,
)

POLICY_FINDING_NAMESPACE = UUID("79c10c39-c6bd-43f5-9d24-37d7fa2c9e69")


@dataclass(frozen=True)
class _RuleMatch:
    observed: object
    locations: tuple[SourceLocation, ...] = ()
    limitations: tuple[str, ...] = ()


def evaluate_policies(
    config: CanonicalConfig,
    *,
    device_id: UUID,
    rules: tuple[PolicyRule, ...] = POLICY_RULES,
) -> list[Finding]:
    """Return policy violations in catalog order for a canonical configuration."""

    platform = _platform_for(config)
    findings: list[Finding] = []
    for rule in rules:
        if platform not in rule.platforms:
            continue
        for match in _evaluate_rule(config, rule):
            affected_lines = sorted(
                {
                    line
                    for location in match.locations
                    for line in location.source_lines
                }
            )
            evidence = [
                Evidence(
                    kind="policy_violation" if index == 0 else "supporting_fact",
                    message=(
                        rule.evidence_message
                        if index == 0
                        else "Additional contributing configuration statement."
                    ),
                    source_location=location,
                )
                for index, location in enumerate(match.locations)
            ]
            if not evidence:
                evidence.append(
                    Evidence(
                        kind="policy_violation",
                        message=rule.evidence_message,
                    )
                )
            findings.append(
                Finding(
                    finding_id=_finding_id(device_id, rule.rule_id, affected_lines),
                    device_id=device_id,
                    detector="policy_engine",
                    category=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=(
                        min(location.parser_confidence for location in match.locations)
                        if match.locations
                        else config.parser_confidence
                    ),
                    anomaly_score=0.0,
                    affected_lines=affected_lines,
                    evidence=evidence,
                    observed={rule.field.value: match.observed},
                    expected={rule.field.value: rule.expected_value},
                    remediation=rule.remediation,
                    references=list(rule.references),
                    limitations=list(match.limitations),
                    model_version=POLICY_CATALOG_VERSION,
                )
            )
    return findings


def _platform_for(config: CanonicalConfig) -> PolicyPlatform:
    if config.device.vendor is Vendor.CISCO and config.device.platform == "ios":
        return PolicyPlatform.CISCO_IOS
    if config.device.vendor is Vendor.JUNIPER and config.device.platform == "junos":
        return PolicyPlatform.JUNIPER_JUNOS
    raise ValueError(
        f"unsupported policy platform: {config.device.vendor.value}/{config.device.platform}"
    )


def _management_value(
    config: CanonicalConfig, field: ManagementField
) -> bool | list[str]:
    if field is ManagementField.SSH_ENABLED:
        return config.management.ssh_enabled
    if field is ManagementField.TELNET_ENABLED:
        return config.management.telnet_enabled
    if field is ManagementField.AAA_ENABLED:
        return config.management.aaa_enabled
    if field is ManagementField.SNMP_VERSIONS:
        return list(config.management.snmp_versions)
    if field is ManagementField.NTP_SERVERS:
        return list(config.management.ntp_servers)
    if field is ManagementField.SYSLOG_SERVERS:
        return list(config.management.syslog_servers)
    raise ValueError(f"unsupported management field: {field}")


def _evaluate_rule(config: CanonicalConfig, rule: PolicyRule) -> list[_RuleMatch]:
    if isinstance(rule.field, AclField):
        return _acl_matches(config, rule.field)
    if isinstance(rule.field, RoutingField):
        return _routing_matches(config, rule.field)
    if isinstance(rule.field, Layer2Field):
        return _layer2_matches(config, rule.field)
    actual = _management_value(config, rule.field)
    if not _is_violation(actual, rule):
        return []
    location = _management_location(config, rule.field)
    if location is not None:
        return [_RuleMatch(observed=actual, locations=(location,))]
    return [
        _RuleMatch(
            observed=actual,
            limitations=(
                "The violation is inferred from the absence of supported configuration syntax.",
            ),
        )
    ]


def _is_violation(actual: bool | list[str], rule: PolicyRule) -> bool:
    if rule.operator is PolicyOperator.EQUALS:
        return actual == rule.violation_value
    if not isinstance(actual, list):
        raise ValueError(f"{rule.operator.value} requires a collection field")
    if rule.operator is PolicyOperator.IS_EMPTY:
        return not actual
    if rule.operator is PolicyOperator.CONTAINS_ANY:
        forbidden = rule.violation_value
        if not isinstance(forbidden, tuple):
            raise ValueError("contains_any requires configured values")
        return bool(set(actual).intersection(forbidden))
    raise ValueError(f"unsupported policy operator: {rule.operator}")


def _management_location(
    config: CanonicalConfig, field: ManagementField
) -> SourceLocation | None:
    return config.management.provenance.get(field.value.removeprefix("management."))


def _acl_matches(config: CanonicalConfig, field: AclField) -> list[_RuleMatch]:
    matches: list[_RuleMatch] = []
    for acl in config.acls:
        if field is AclField.EMPTY and not acl.rules:
            location = acl.provenance.get("name")
            matches.append(
                _RuleMatch(
                    observed={"acl": acl.name, "family": acl.family},
                    locations=() if location is None else (location,),
                )
            )
            continue
        for acl_rule in acl.rules:
            if _acl_rule_matches(acl_rule, field):
                matches.append(
                    _RuleMatch(
                        observed=_acl_observed(acl, acl_rule),
                        locations=_acl_rule_locations(acl_rule),
                    )
                )
    return matches


def _acl_rule_matches(rule: AclRule, field: AclField) -> bool:
    if rule.action != "permit":
        return False
    source_unrestricted = not rule.source_addresses or "any" in rule.source_addresses
    destination_unrestricted = (
        not rule.destination_addresses or "any" in rule.destination_addresses
    )
    if field is AclField.UNRESTRICTED_PERMIT:
        return (
            source_unrestricted
            and destination_unrestricted
            and not rule.source_ports
            and not rule.destination_ports
        )
    if field is AclField.TELNET_PERMITTED:
        return _ports_include(rule.destination_ports, {"23", "telnet"})
    if field is AclField.MANAGEMENT_ACCESS_FROM_ANY:
        return source_unrestricted and _ports_include(
            rule.destination_ports, {"22", "161", "162", "ssh", "snmp", "snmptrap"}
        )
    return False


def _ports_include(expressions: list[str], targets: set[str]) -> bool:
    for expression in expressions:
        normalized = expression.lower()
        if normalized in targets:
            return True
        operator, separator, operands = normalized.partition(":")
        if separator and operator == "eq" and operands in targets:
            return True
    return False


def _acl_observed(acl: AclConfig, rule: AclRule) -> dict[str, object]:
    return {
        "acl": acl.name,
        "family": acl.family,
        "rule": rule.sequence if rule.sequence is not None else rule.term,
        "action": rule.action,
        "protocol": rule.protocol,
        "source_addresses": rule.source_addresses,
        "destination_addresses": rule.destination_addresses,
        "destination_ports": rule.destination_ports,
    }


def _acl_rule_locations(rule: AclRule) -> tuple[SourceLocation, ...]:
    whole_rule = rule.provenance.get("rule")
    if whole_rule is not None:
        return (whole_rule,)
    return _unique_locations(list(rule.provenance.values()))


def _routing_matches(
    config: CanonicalConfig, field: RoutingField
) -> list[_RuleMatch]:
    if field is RoutingField.BGP_ROUTER_ID_MISSING:
        if config.bgp is None or config.bgp.router_id is not None:
            return []
        location = config.bgp.provenance.get("local_as")
        return [
            _RuleMatch(
                observed={"local_as": config.bgp.local_as, "router_id": None},
                locations=() if location is None else (location,),
                limitations=(
                    "The missing router ID is inferred from supported configuration syntax.",
                ),
            )
        ]
    if field is RoutingField.BGP_NEIGHBOR_IS_LOCAL:
        return _local_bgp_neighbor_matches(config)
    if field is RoutingField.OSPF_ROUTER_ID_MISSING:
        matches: list[_RuleMatch] = []
        for process in config.ospf:
            if process.router_id is not None:
                continue
            location = process.provenance.get("process_id")
            matches.append(
                _RuleMatch(
                    observed={"process_id": process.process_id, "router_id": None},
                    locations=() if location is None else (location,),
                    limitations=(
                        "The missing router ID is inferred from supported configuration syntax.",
                    ),
                )
            )
        return matches
    if field is RoutingField.DEFAULT_ROUTE_DISCARDED:
        return [
            _RuleMatch(
                observed={
                    "family": route.family,
                    "destination": route.destination,
                    "discard": route.discard,
                },
                locations=_unique_locations(list(route.provenance.values())),
            )
            for route in config.static_routes
            if route.discard and ip_network(route.destination).prefixlen == 0
        ]
    return []


def _local_bgp_neighbor_matches(config: CanonicalConfig) -> list[_RuleMatch]:
    if config.bgp is None:
        return []
    local_addresses: dict[str, list[SourceLocation]] = {}
    for interface in config.interfaces:
        for address in interface.addresses:
            host = str(ip_interface(address.address).ip)
            local_addresses.setdefault(host, []).append(address.provenance)
    matches: list[_RuleMatch] = []
    for neighbor in config.bgp.neighbors:
        interface_locations = local_addresses.get(neighbor.address)
        if interface_locations is None:
            continue
        locations = list(interface_locations)
        neighbor_location = neighbor.provenance.get("address")
        if neighbor_location is not None:
            locations.append(neighbor_location)
        matches.append(
            _RuleMatch(
                observed={
                    "neighbor": neighbor.address,
                    "local_interface_address": neighbor.address,
                },
                locations=_unique_locations(locations),
            )
        )
    return matches


def _unique_locations(
    candidates: list[SourceLocation],
) -> tuple[SourceLocation, ...]:
    locations: list[SourceLocation] = []
    seen: set[tuple[tuple[int, ...], str]] = set()
    for location in sorted(
        candidates, key=lambda item: item.source_lines[0]
    ):
        key = (tuple(location.source_lines), location.raw_text_hash)
        if key not in seen:
            locations.append(location)
            seen.add(key)
    return tuple(locations)


def _layer2_matches(config: CanonicalConfig, field: Layer2Field) -> list[_RuleMatch]:
    matches: list[_RuleMatch] = []
    for interface in config.interfaces:
        if field is Layer2Field.ACCESS_VLAN_MISSING:
            if (
                interface.switchport_mode == "access"
                and interface.access_vlan is None
                and interface.native_vlan is None
                and interface.allowed_vlans is None
            ):
                matches.append(
                    _RuleMatch(
                        observed=_interface_observed(interface),
                        locations=_interface_locations(interface, "switchport_mode"),
                        limitations=(
                            "The missing access VLAN is inferred from supported "
                            "configuration syntax.",
                        ),
                    )
                )
        elif field is Layer2Field.TRUNK_VLANS_UNRESTRICTED:
            if (
                interface.switchport_mode == "trunk"
                and interface.access_vlan is None
                and (
                    interface.allowed_vlans is None
                    or interface.allowed_vlans.all_vlans
                )
            ):
                locations = _interface_locations(interface, "switchport_mode")
                limitations: tuple[str, ...] = ()
                if interface.allowed_vlans is None:
                    limitations = (
                        "The unrestricted VLAN set is inferred from the absence of "
                        "supported restriction syntax.",
                    )
                else:
                    locations = _unique_locations(
                        [*locations, interface.allowed_vlans.provenance]
                    )
                matches.append(
                    _RuleMatch(
                        observed=_interface_observed(interface),
                        locations=locations,
                        limitations=limitations,
                    )
                )
        elif field is Layer2Field.SWITCHPORT_MODE_CONFLICT and (
            (
                interface.switchport_mode == "access"
                and (
                    interface.native_vlan is not None
                    or interface.allowed_vlans is not None
                )
            )
            or (
                interface.switchport_mode == "trunk"
                and interface.access_vlan is not None
            )
        ):
            matches.append(
                _RuleMatch(
                    observed=_interface_observed(interface),
                    locations=_conflicting_interface_locations(interface),
                )
            )
    return matches


def _interface_observed(interface: InterfaceConfig) -> dict[str, object]:
    return {
        "name": interface.name,
        "unit": interface.unit,
        "switchport_mode": interface.switchport_mode,
        "access_vlan": (
            None
            if interface.access_vlan is None
            else {
                "vlan_id": interface.access_vlan.vlan_id,
                "name": interface.access_vlan.name,
            }
        ),
        "native_vlan": (
            None
            if interface.native_vlan is None
            else {
                "vlan_id": interface.native_vlan.vlan_id,
                "name": interface.native_vlan.name,
            }
        ),
        "allowed_vlans": (
            None
            if interface.allowed_vlans is None
            else {
                "vlan_ids": interface.allowed_vlans.vlan_ids,
                "vlan_names": interface.allowed_vlans.vlan_names,
                "all_vlans": interface.allowed_vlans.all_vlans,
            }
        ),
    }


def _interface_locations(
    interface: InterfaceConfig, *keys: str
) -> tuple[SourceLocation, ...]:
    return _unique_locations(
        [interface.provenance[key] for key in keys if key in interface.provenance]
    )


def _conflicting_interface_locations(
    interface: InterfaceConfig,
) -> tuple[SourceLocation, ...]:
    locations = list(_interface_locations(interface, "switchport_mode"))
    if interface.access_vlan is not None:
        locations.append(interface.access_vlan.provenance)
    if interface.native_vlan is not None:
        locations.append(interface.native_vlan.provenance)
    if interface.allowed_vlans is not None:
        locations.append(interface.allowed_vlans.provenance)
    return _unique_locations(locations)


def _finding_id(device_id: UUID, rule_id: str, affected_lines: list[int]) -> UUID:
    line_key = ",".join(str(line) for line in affected_lines)
    return uuid5(POLICY_FINDING_NAMESPACE, f"{device_id}:{rule_id}:{line_key}")
