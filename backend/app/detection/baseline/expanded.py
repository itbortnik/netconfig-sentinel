"""Opt-in second-generation facts; the released six-field detector is unchanged."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from enum import StrEnum
from ipaddress import ip_address
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from app.domain import CanonicalConfig, Evidence, Finding, Severity, SourceLocation, Vendor
from app.domain.models import AclConfig, PrefixListConfig

EXPANDED_REFERENCE_NAMESPACE = UUID("ea42aeb4-b12e-4491-9a2f-2b6edbf1c1c7")
MAX_FACTS = 50_000
MAX_FACT_VALUE_BYTES = 512 * 1024
MAX_PROJECTION_BYTES = 8 * 1024 * 1024
type ExpandedValue = StrictBool | StrictInt | StrictStr | tuple[StrictStr, ...] | None


class ExpandedField(StrEnum):
    SSH_ENABLED = "management.ssh_enabled"
    SSH_VERSION = "management.ssh_version"
    TELNET_ENABLED = "management.telnet_enabled"
    AAA_ENABLED = "management.aaa_enabled"
    SNMP_VERSIONS = "management.snmp_versions"
    NTP_SERVERS = "management.ntp_servers"
    SYSLOG_SERVERS = "management.syslog_servers"
    USER_PRESENT = "local_user.present"
    USER_PRIVILEGE = "local_user.privilege"
    USER_LOGIN_CLASS = "local_user.login_class"
    USER_UID = "local_user.uid"
    USER_AUTHENTICATION = "local_user.authentication"
    INTERFACE_PRESENT = "interface.present"
    INTERFACE_ENABLED = "interface.enabled"
    INTERFACE_MODE = "interface.mode"
    INTERFACE_ACCESS_VLAN = "interface.access_vlan"
    INTERFACE_NATIVE_VLAN = "interface.native_vlan"
    INTERFACE_ALLOWED_VLANS = "interface.allowed_vlans"
    INTERFACE_ADDRESSES = "interface.addresses"
    VLAN_SET = "vlans.set"
    ACL_PRESENT = "acls.present"
    ACL_RULES = "acls.rules"
    PREFIX_PRESENT = "prefix_lists.present"
    PREFIX_RULES = "prefix_lists.rules"
    BGP_PRESENT = "bgp.present"
    BGP_LOCAL_AS = "bgp.local_as"
    BGP_ROUTER_ID = "bgp.router_id"
    BGP_NEIGHBOR_PRESENT = "bgp.neighbor.present"
    BGP_REMOTE_AS = "bgp.neighbor.remote_as"
    BGP_GROUP = "bgp.neighbor.group"
    BGP_SESSION_TYPE = "bgp.neighbor.session_type"
    BGP_UPDATE_SOURCE = "bgp.neighbor.update_source"
    BGP_ENABLED = "bgp.neighbor.enabled"
    BGP_FAMILY = "bgp.neighbor.family"
    OSPF_PRESENT = "ospf.present"
    OSPF_PROCESS_PRESENT = "ospf.process.present"
    OSPF_VERSION = "ospf.process.version"
    OSPF_ROUTER_ID = "ospf.process.router_id"
    OSPF_PASSIVE_DEFAULT = "ospf.process.passive_default"
    OSPF_NETWORK_AREA = "ospf.network.area"
    OSPF_INTERFACE_PRESENT = "ospf.interface.present"
    OSPF_INTERFACE_AREA = "ospf.interface.area"
    OSPF_INTERFACE_PASSIVE = "ospf.interface.passive"
    OSPF_INTERFACE_COST = "ospf.interface.cost"
    STATIC_TARGETS = "static_routes.targets"


_BOOLEAN_FIELDS = {
    ExpandedField.SSH_ENABLED,
    ExpandedField.TELNET_ENABLED,
    ExpandedField.AAA_ENABLED,
    ExpandedField.USER_PRESENT,
    ExpandedField.INTERFACE_PRESENT,
    ExpandedField.ACL_PRESENT,
    ExpandedField.PREFIX_PRESENT,
    ExpandedField.BGP_PRESENT,
    ExpandedField.BGP_NEIGHBOR_PRESENT,
    ExpandedField.OSPF_PRESENT,
    ExpandedField.OSPF_PROCESS_PRESENT,
    ExpandedField.OSPF_PASSIVE_DEFAULT,
    ExpandedField.OSPF_INTERFACE_PRESENT,
}
_OPTIONAL_BOOLEAN_FIELDS = {
    ExpandedField.INTERFACE_ENABLED,
    ExpandedField.BGP_ENABLED,
    ExpandedField.OSPF_INTERFACE_PASSIVE,
}
_INTEGER_FIELDS = {ExpandedField.BGP_LOCAL_AS, ExpandedField.BGP_REMOTE_AS}
_OPTIONAL_INTEGER_FIELDS = {
    ExpandedField.USER_PRIVILEGE,
    ExpandedField.USER_UID,
    ExpandedField.OSPF_INTERFACE_COST,
}
_TUPLE_FIELDS = {
    ExpandedField.SNMP_VERSIONS,
    ExpandedField.NTP_SERVERS,
    ExpandedField.SYSLOG_SERVERS,
    ExpandedField.USER_AUTHENTICATION,
    ExpandedField.INTERFACE_ADDRESSES,
    ExpandedField.VLAN_SET,
    ExpandedField.ACL_RULES,
    ExpandedField.PREFIX_RULES,
    ExpandedField.STATIC_TARGETS,
}
_TWO_PART_KEYS = {field for field in ExpandedField if field.value.startswith("interface.")} | {
    ExpandedField.PREFIX_PRESENT,
    ExpandedField.PREFIX_RULES,
    ExpandedField.OSPF_NETWORK_AREA,
    ExpandedField.OSPF_INTERFACE_PRESENT,
    ExpandedField.OSPF_INTERFACE_AREA,
    ExpandedField.OSPF_INTERFACE_PASSIVE,
    ExpandedField.OSPF_INTERFACE_COST,
    ExpandedField.STATIC_TARGETS,
}
_ROOT_FIELDS = {field for field in ExpandedField if field.value.startswith("management.")} | {
    ExpandedField.VLAN_SET,
    ExpandedField.BGP_PRESENT,
    ExpandedField.BGP_LOCAL_AS,
    ExpandedField.BGP_ROUTER_ID,
    ExpandedField.OSPF_PRESENT,
}


def encoded_value(value: object) -> str:
    """An unambiguous JSON signature, not a vendor command or executable expression."""
    result = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(result.encode("utf-8")) > MAX_FACT_VALUE_BYTES:
        raise ValueError("expanded comparison value exceeds its bounded contract")
    return result


def value_digest(value: object) -> str:
    return hashlib.sha256(encoded_value(value).encode("utf-8")).hexdigest()


def unique_locations(locations: list[SourceLocation]) -> tuple[SourceLocation, ...]:
    ordered = sorted(
        locations,
        key=lambda item: (tuple(item.source_lines), item.raw_text_hash, item.parser_confidence),
    )
    indexed = {encoded_value(item.model_dump(mode="json")): item for item in ordered}
    return tuple(indexed.values())


def complete_config(config: CanonicalConfig) -> CanonicalConfig:
    validated = CanonicalConfig.model_validate(config.model_dump())
    if validated.parse_warnings or validated.unparsed_fragments or validated.parser_confidence != 1:
        raise ValueError("expanded property comparison requires complete parsing")
    return validated


class ExpandedFact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    field: ExpandedField
    object_key: tuple[str, ...] = Field(min_length=1, max_length=3)
    value: ExpandedValue
    locations: tuple[SourceLocation, ...] = Field(default=(), max_length=10_000)

    @model_validator(mode="after")
    def bounded_typed_fact(self) -> ExpandedFact:
        size = (
            3
            if self.field in {ExpandedField.ACL_PRESENT, ExpandedField.ACL_RULES}
            else (2 if self.field in _TWO_PART_KEYS else 1)
        )
        if (
            len(self.object_key) != size
            or any(len(item) > 512 or (item and not item.isprintable()) for item in self.object_key)
            or not self.object_key[0]
            or any(
                not item
                for item in self.object_key[1:]
                if self.field
                not in {field for field in ExpandedField if field.value.startswith("interface.")}
            )
        ):
            raise ValueError("invalid expanded fact identity")
        if self.field in _ROOT_FIELDS and self.object_key != ("device",):
            raise ValueError("global expanded facts require the device key")
        allowed: tuple[type[object], ...]
        if self.field in _BOOLEAN_FIELDS:
            allowed = (bool,)
        elif self.field in _OPTIONAL_BOOLEAN_FIELDS:
            allowed = (bool, type(None))
        elif self.field in _INTEGER_FIELDS:
            allowed = (int,)
        elif self.field in _OPTIONAL_INTEGER_FIELDS:
            allowed = (int, type(None))
        elif self.field in _TUPLE_FIELDS:
            allowed = (tuple,)
        elif self.field in {
            ExpandedField.BGP_FAMILY,
            ExpandedField.OSPF_VERSION,
            ExpandedField.OSPF_NETWORK_AREA,
        }:
            allowed = (str,)
        else:
            allowed = (str, type(None))
        if type(self.value) not in allowed:
            raise ValueError("expanded fact value has the wrong primitive type")
        if (
            self.field.value.endswith(".present")
            and self.field
            not in {
                ExpandedField.BGP_PRESENT,
                ExpandedField.OSPF_PRESENT,
            }
            and self.value is not True
        ):
            raise ValueError("an object presence fact must be true")
        choices: dict[ExpandedField, set[str | None]] = {
            ExpandedField.SSH_VERSION: {None, "1", "2"},
            ExpandedField.INTERFACE_MODE: {None, "access", "trunk"},
            ExpandedField.BGP_SESSION_TYPE: {None, "internal", "external"},
            ExpandedField.BGP_FAMILY: {"ipv4", "ipv6"},
            ExpandedField.OSPF_VERSION: {"ospfv2"},
        }
        if self.field in choices and self.value not in choices[self.field]:
            raise ValueError("unsupported expanded fact value")
        ranges = {
            ExpandedField.USER_PRIVILEGE: (0, 15),
            ExpandedField.USER_UID: (100, 64_000),
            ExpandedField.BGP_LOCAL_AS: (1, 4_294_967_295),
            ExpandedField.BGP_REMOTE_AS: (1, 4_294_967_295),
            ExpandedField.OSPF_INTERFACE_COST: (1, 65_535),
        }
        if self.field in ranges and isinstance(self.value, int):
            lower, upper = ranges[self.field]
            if not lower <= self.value <= upper:
                raise ValueError("expanded numeric fact is outside its supported range")
        if self.field in {
            ExpandedField.BGP_ROUTER_ID,
            ExpandedField.OSPF_ROUTER_ID,
            ExpandedField.OSPF_NETWORK_AREA,
            ExpandedField.OSPF_INTERFACE_AREA,
        }:
            if self.value is not None and (
                not isinstance(self.value, str)
                or ip_address(self.value).version != 4
                or str(ip_address(self.value)) != self.value
            ):
                raise ValueError("expanded routing identifier must be canonical IPv4")
        if self.field in {
            ExpandedField.SNMP_VERSIONS,
            ExpandedField.NTP_SERVERS,
            ExpandedField.SYSLOG_SERVERS,
            ExpandedField.INTERFACE_ADDRESSES,
            ExpandedField.VLAN_SET,
            ExpandedField.USER_AUTHENTICATION,
            ExpandedField.STATIC_TARGETS,
        }:
            if not isinstance(self.value, tuple) or self.value != tuple(sorted(set(self.value))):
                raise ValueError("expanded set fact must be sorted and unique")
        if (
            self.field is ExpandedField.SNMP_VERSIONS
            and isinstance(self.value, tuple)
            and (not set(self.value) <= {"v1", "v2c", "v3"})
        ):
            raise ValueError("unsupported SNMP version")
        encoded_value(self.value)
        return self


def acl_rows(acl: AclConfig, *, include_labels: bool) -> tuple[str, ...]:
    rows = []
    for rule in acl.rules:
        values: list[object] = [
            rule.action,
            rule.protocol,
            sorted(set(rule.source_addresses)),
            sorted(set(rule.destination_addresses)),
            rule.source_ports,
            rule.destination_ports,
            rule.options,
        ]
        if include_labels:
            values.extend([rule.sequence, rule.term])
        rows.append(encoded_value(values))
    return tuple(rows)


def prefix_rows(prefix: PrefixListConfig, *, include_labels: bool) -> tuple[str, ...]:
    return tuple(
        encoded_value(
            [rule.action, rule.prefix, rule.ge, rule.le]
            + ([rule.sequence] if include_labels else [])
        )
        for rule in prefix.rules
    )


def project_expanded_facts(config: CanonicalConfig) -> tuple[ExpandedFact, ...]:
    """Project supported IR only: no source text, credential values or inferred effective state."""
    config = complete_config(config)
    facts: list[ExpandedFact] = []
    key: tuple[str, ...]
    value: ExpandedValue

    def add(
        field: ExpandedField,
        key: tuple[str, ...],
        value: ExpandedValue,
        locations: list[SourceLocation],
    ) -> None:
        facts.append(
            ExpandedFact(
                field=field, object_key=key, value=value, locations=unique_locations(locations)
            )
        )
        if len(facts) > MAX_FACTS:
            raise ValueError("expanded comparison projection exceeds its fact limit")

    management = config.management
    for field, value in (
        (ExpandedField.SSH_ENABLED, management.ssh_enabled),
        (ExpandedField.SSH_VERSION, management.ssh_version),
        (ExpandedField.TELNET_ENABLED, management.telnet_enabled),
        (ExpandedField.AAA_ENABLED, management.aaa_enabled),
        (ExpandedField.SNMP_VERSIONS, tuple(sorted(set(management.snmp_versions)))),
        (ExpandedField.NTP_SERVERS, tuple(sorted(set(management.ntp_servers)))),
        (ExpandedField.SYSLOG_SERVERS, tuple(sorted(set(management.syslog_servers)))),
    ):
        location = management.provenance.get(field.value.split(".")[1])
        add(field, ("device",), value, [] if location is None else [location])
    for user in config.local_users:
        key = (user.name,)
        add(ExpandedField.USER_PRESENT, key, True, list(user.provenance.values()))
        for field, value in (
            (ExpandedField.USER_PRIVILEGE, user.privilege),
            (ExpandedField.USER_LOGIN_CLASS, user.login_class),
            (ExpandedField.USER_UID, user.uid),
        ):
            location = user.provenance.get(field.value.split(".")[1])
            add(field, key, value, [] if location is None else [location])
        add(
            ExpandedField.USER_AUTHENTICATION,
            key,
            tuple(
                sorted(encoded_value([item.kind, item.encoding]) for item in user.authentication)
            ),
            [item.provenance for item in user.authentication],
        )
    for interface in config.interfaces:
        key = (interface.name, interface.unit or "")
        add(ExpandedField.INTERFACE_PRESENT, key, True, list(interface.provenance.values()))
        for field, value, source_key in (
            (ExpandedField.INTERFACE_ENABLED, interface.enabled, "enabled"),
            (ExpandedField.INTERFACE_MODE, interface.switchport_mode, "switchport_mode"),
        ):
            location = interface.provenance.get(source_key)
            add(field, key, value, [] if location is None else [location])
        for field, vlan in (
            (ExpandedField.INTERFACE_ACCESS_VLAN, interface.access_vlan),
            (ExpandedField.INTERFACE_NATIVE_VLAN, interface.native_vlan),
        ):
            add(
                field,
                key,
                None if vlan is None else encoded_value([vlan.vlan_id, vlan.name]),
                [] if vlan is None else [vlan.provenance],
            )
        allowed = interface.allowed_vlans
        add(
            ExpandedField.INTERFACE_ALLOWED_VLANS,
            key,
            None
            if allowed is None
            else encoded_value([allowed.all_vlans, allowed.vlan_ids, sorted(allowed.vlan_names)]),
            [] if allowed is None else [allowed.provenance],
        )
        add(
            ExpandedField.INTERFACE_ADDRESSES,
            key,
            tuple(sorted({item.address for item in interface.addresses})),
            [item.provenance for item in interface.addresses],
        )
    vlan_keys = [
        ("id", str(vlan.vlan_id)) if vlan.vlan_id is not None else ("name", vlan.name)
        for vlan in config.vlans
    ]
    if len(vlan_keys) != len(set(vlan_keys)):
        raise ValueError("ambiguous duplicate VLAN objects")
    add(
        ExpandedField.VLAN_SET,
        ("device",),
        tuple(sorted(encoded_value([vlan.vlan_id, vlan.name]) for vlan in config.vlans)),
        [location for vlan in config.vlans for location in vlan.provenance.values()],
    )
    acl_keys = [(acl.name, acl.family) for acl in config.acls]
    if len(acl_keys) != len(set(acl_keys)):
        raise ValueError("ambiguous duplicate ACL objects")
    for acl in config.acls:
        key = (acl.name, acl.family, acl.kind)
        add(ExpandedField.ACL_PRESENT, key, True, list(acl.provenance.values()))
        add(
            ExpandedField.ACL_RULES,
            key,
            acl_rows(acl, include_labels=True),
            [location for rule in acl.rules for location in rule.provenance.values()],
        )
    for prefix in config.prefix_lists:
        key = (prefix.name, prefix.family)
        add(ExpandedField.PREFIX_PRESENT, key, True, list(prefix.provenance.values()))
        add(
            ExpandedField.PREFIX_RULES,
            key,
            prefix_rows(prefix, include_labels=True),
            [rule.provenance for rule in prefix.rules],
        )
    bgp = config.bgp
    add(
        ExpandedField.BGP_PRESENT,
        ("device",),
        bgp is not None,
        [] if bgp is None else list(bgp.provenance.values()),
    )
    if bgp is not None:
        for field, value in (
            (ExpandedField.BGP_LOCAL_AS, bgp.local_as),
            (ExpandedField.BGP_ROUTER_ID, bgp.router_id),
        ):
            location = bgp.provenance.get(field.value.split(".")[1])
            add(field, ("device",), value, [] if location is None else [location])
        for neighbor in bgp.neighbors:
            key = (neighbor.address,)
            add(ExpandedField.BGP_NEIGHBOR_PRESENT, key, True, list(neighbor.provenance.values()))
            for field, value in (
                (ExpandedField.BGP_REMOTE_AS, neighbor.remote_as),
                (ExpandedField.BGP_GROUP, neighbor.group),
                (ExpandedField.BGP_SESSION_TYPE, neighbor.session_type),
                (ExpandedField.BGP_UPDATE_SOURCE, neighbor.update_source),
                (ExpandedField.BGP_ENABLED, neighbor.enabled),
                (ExpandedField.BGP_FAMILY, neighbor.family),
            ):
                location = neighbor.provenance.get(field.value.split(".")[-1])
                add(field, key, value, [] if location is None else [location])
    add(
        ExpandedField.OSPF_PRESENT,
        ("device",),
        bool(config.ospf),
        [location for process in config.ospf for location in process.provenance.values()],
    )
    for process in config.ospf:
        key = (process.process_id,)
        add(ExpandedField.OSPF_PROCESS_PRESENT, key, True, list(process.provenance.values()))
        for field, value in (
            (ExpandedField.OSPF_VERSION, process.version),
            (ExpandedField.OSPF_ROUTER_ID, process.router_id),
            (ExpandedField.OSPF_PASSIVE_DEFAULT, process.passive_default),
        ):
            location = process.provenance.get(field.value.split(".")[-1])
            add(field, key, value, [] if location is None else [location])
        for network in process.networks:
            add(
                ExpandedField.OSPF_NETWORK_AREA,
                (process.process_id, network.prefix),
                network.area_id,
                [network.provenance],
            )
        for ospf_interface in process.interfaces:
            key = (process.process_id, ospf_interface.name)
            add(
                ExpandedField.OSPF_INTERFACE_PRESENT,
                key,
                True,
                list(ospf_interface.provenance.values()),
            )
            for field, value, source_key in (
                (ExpandedField.OSPF_INTERFACE_AREA, ospf_interface.area_id, "area_id"),
                (ExpandedField.OSPF_INTERFACE_PASSIVE, ospf_interface.passive, "passive"),
                (ExpandedField.OSPF_INTERFACE_COST, ospf_interface.cost, "cost"),
            ):
                location = ospf_interface.provenance.get(source_key)
                add(field, key, value, [] if location is None else [location])
    targets: dict[tuple[str, str], list[str]] = defaultdict(list)
    target_locations: dict[tuple[str, str], list[SourceLocation]] = defaultdict(list)
    route_key: tuple[str, str]
    for route in config.static_routes:
        route_key = (route.family, route.destination)
        targets[route_key].append(
            encoded_value(
                [route.next_hop, route.outgoing_interface, route.preference, route.discard]
            )
        )
        target_locations[route_key].extend(route.provenance.values())
    for route_key, rows in targets.items():
        add(
            ExpandedField.STATIC_TARGETS,
            route_key,
            tuple(sorted(set(rows))),
            target_locations[route_key],
        )
    keys = [(fact.field, fact.object_key) for fact in facts]
    if len(keys) != len(set(keys)):
        raise ValueError("ambiguous duplicate expanded configuration facts")
    if sum(len(fact.model_dump_json().encode("utf-8")) for fact in facts) > MAX_PROJECTION_BYTES:
        raise ValueError("expanded comparison projection exceeds its byte limit")
    return tuple(sorted(facts, key=lambda item: (item.field.value, item.object_key)))


class ExpandedReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["expected-config-0.2.0"] = "expected-config-0.2.0"
    reference_id: str = Field(min_length=1, max_length=256)
    device_id: UUID
    vendor: Vendor
    platform: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    facts: tuple[ExpandedFact, ...] = Field(min_length=1, max_length=MAX_FACTS)

    @model_validator(mode="after")
    def unique_bounded_facts(self) -> ExpandedReference:
        keys = [(fact.field, fact.object_key) for fact in self.facts]
        if len(keys) != len(set(keys)):
            raise ValueError("ambiguous duplicate expanded reference facts")
        if keys != sorted(keys, key=lambda item: (item[0].value, item[1])):
            raise ValueError("expanded reference facts must have canonical order")
        indexed = dict(zip(keys, self.facts, strict=True))
        roots = {field for field in ExpandedField if field.value.startswith("management.")} | {
            ExpandedField.VLAN_SET,
            ExpandedField.BGP_PRESENT,
            ExpandedField.OSPF_PRESENT,
        }
        if any((field, ("device",)) not in indexed for field in roots):
            raise ValueError("expanded reference is missing its root fact inventory")
        for prefix in (
            "local_user.",
            "interface.",
            "acls.",
            "prefix_lists.",
            "bgp.neighbor.",
            "ospf.process.",
            "ospf.interface.",
        ):
            fields = {field for field in ExpandedField if field.value.startswith(prefix)}
            object_keys = {fact.object_key for fact in self.facts if fact.field in fields}
            if any((field, key) not in indexed for key in object_keys for field in fields):
                raise ValueError("expanded reference has an incomplete object fact inventory")
        bgp_present = indexed[(ExpandedField.BGP_PRESENT, ("device",))].value
        bgp_details = [
            fact
            for fact in self.facts
            if fact.field.value.startswith("bgp.") and fact.field is not ExpandedField.BGP_PRESENT
        ]
        if bgp_present:
            if any(
                (field, ("device",)) not in indexed
                for field in (
                    ExpandedField.BGP_LOCAL_AS,
                    ExpandedField.BGP_ROUTER_ID,
                )
            ):
                raise ValueError("expanded BGP process requires its supported facts")
        elif bgp_details:
            raise ValueError("absent BGP process cannot contain supported facts")
        ospf_present = indexed[(ExpandedField.OSPF_PRESENT, ("device",))].value
        ospf_processes = {
            fact.object_key[0]
            for fact in self.facts
            if fact.field is ExpandedField.OSPF_PROCESS_PRESENT
        }
        ospf_details = [
            fact
            for fact in self.facts
            if fact.field.value.startswith("ospf.") and fact.field is not ExpandedField.OSPF_PRESENT
        ]
        if bool(ospf_processes) != ospf_present or any(
            fact.object_key[0] not in ospf_processes for fact in ospf_details
        ):
            raise ValueError("expanded OSPF facts require their declared processes")
        if (
            sum(len(fact.model_dump_json().encode("utf-8")) for fact in self.facts)
            > MAX_PROJECTION_BYTES
        ):
            raise ValueError("expanded reference exceeds its byte limit")
        return self

    def fingerprint(self) -> str:
        # The complete bounded reference can exceed a single fact-value limit.
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def create_expanded_reference(
    config: CanonicalConfig,
    *,
    device_id: UUID,
    reference_id: str,
) -> ExpandedReference:
    config = complete_config(config)
    return ExpandedReference(
        reference_id=reference_id,
        device_id=device_id,
        vendor=config.device.vendor,
        platform=config.device.platform,
        hostname=config.device.hostname,
        source_sha256=config.source.sha256,
        facts=project_expanded_facts(config),
    )


def compare_expanded_reference(
    config: CanonicalConfig,
    reference: ExpandedReference,
    *,
    device_id: UUID,
) -> list[Finding]:
    config = complete_config(config)
    reference = ExpandedReference.model_validate(reference.model_dump())
    if (device_id, config.device.vendor, config.device.platform, config.device.hostname) != (
        reference.device_id,
        reference.vendor,
        reference.platform,
        reference.hostname,
    ):
        raise ValueError("configuration identity differs from the selected expanded reference")
    expected = {(fact.field, fact.object_key): fact for fact in reference.facts}
    observed = {(fact.field, fact.object_key): fact for fact in project_expanded_facts(config)}
    digest = reference.fingerprint()
    findings: list[Finding] = []
    for key in sorted(expected.keys() | observed.keys(), key=lambda item: (item[0].value, item[1])):
        before, after = expected.get(key), observed.get(key)
        if (
            before is not None
            and after is not None
            and encoded_value(before.value) == encoded_value(after.value)
        ):
            continue
        current_locations = () if after is None else after.locations
        reference_lines = (
            []
            if before is None
            else sorted({line for location in before.locations for line in location.source_lines})
        )
        limitations = [
            "A normalized reference difference is review information, not proof of a fault.",
            "The selected reference is not independently approved; MEDIUM is a review priority.",
            "Only supported IR fields are compared; "
            "null does not imply an effective vendor default.",
            "No network simulation, ML evaluation, credential comparison or device change was run.",
            "Scores are exact-difference indicators, not calibrated fault probabilities.",
        ]
        if not current_locations:
            limitations.append(
                "No current source anchor exists; reference lines are not affected current lines."
            )
        identity = encoded_value(
            [
                str(device_id),
                reference.version,
                reference.reference_id,
                digest,
                config.source.sha256,
                key,
                after is not None,
                None if after is None else value_digest(after.value),
            ]
        )
        findings.append(
            Finding(
                finding_id=uuid5(EXPANDED_REFERENCE_NAMESPACE, identity),
                device_id=device_id,
                detector="expected_configuration",
                model_version=reference.version,
                category=f"baseline.expected.{key[0].value}",
                title=f"Expanded reference deviation: {key[0].value} on {' / '.join(key[1])}",
                severity=Severity.MEDIUM,
                confidence=1.0,
                anomaly_score=1.0,
                affected_lines=sorted(
                    {line for loc in current_locations for line in loc.source_lines}
                ),
                evidence=[
                    Evidence(
                        kind="current_configuration",
                        message="Current supported normalized fact.",
                        source_location=location,
                    )
                    for location in current_locations
                ]
                + [
                    Evidence(
                        kind="explicit_reference",
                        message=(
                            f"Selected reference {reference.reference_id}, "
                            f"SHA-256 {reference.source_sha256}."
                        ),
                    )
                ],
                observed={
                    "object_key": key[1],
                    "present": after is not None,
                    "value": None if after is None else after.value,
                    "source_sha256": config.source.sha256,
                },
                expected={
                    "object_key": key[1],
                    "present": before is not None,
                    "value": None if before is None else before.value,
                    "reference_id": reference.reference_id,
                    "source_sha256": reference.source_sha256,
                    "reference_facts_sha256": digest,
                    "reference_lines": reference_lines,
                },
                remediation="Review the intended change against the selected device reference "
                "before acting.",
                references=["docs/expanded-comparisons.md#same-device-reference"],
                limitations=limitations,
            )
        )
    return findings
