"""Conservative JunOS parser for set-style and hierarchical management config."""

from __future__ import annotations

import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_interface, ip_network
from typing import Literal

from app.domain import (
    AclConfig,
    AclRule,
    BgpConfig,
    BgpNeighborConfig,
    CanonicalConfig,
    DeviceInfo,
    InterfaceAddress,
    InterfaceConfig,
    ManagementConfig,
    OspfInterfaceConfig,
    OspfProcessConfig,
    PrefixListConfig,
    PrefixListRule,
    StaticRouteConfig,
    UnparsedFragment,
    Vendor,
    VlanConfig,
    VlanReference,
    VlanSet,
)
from app.parsers.base import VendorParser, config_source, source_location
from app.parsers.cisco_ios.parser import _overall_confidence

_SAFE_BLOCKS = {
    "system",
    "services",
    "ntp",
    "syslog",
    "snmp",
    "v3",
    "usm",
    "local-engine",
    "community",
    "host",
    "radius-server",
    "tacplus-server",
}


@dataclass
class _JunosInterface:
    name: str
    unit: str | None
    description: str | None = None
    enabled: bool | None = None
    addresses: list[InterfaceAddress] = field(default_factory=list)
    switchport_mode: Literal["access", "trunk"] | None = None
    vlan_members: list[str] = field(default_factory=list)
    vlan_member_sources: list[tuple[int, str]] = field(default_factory=list)
    all_vlans: bool = False
    native_vlan_id: int | None = None
    native_vlan_source: tuple[int, str] | None = None
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(
        self,
        base: _JunosInterface | None = None,
        vlan_ids_by_name: dict[str, int] | None = None,
    ) -> InterfaceConfig:
        description = self.description
        enabled = self.enabled
        switchport_mode = self.switchport_mode
        vlan_members = self.vlan_members
        vlan_member_sources = self.vlan_member_sources
        all_vlans = self.all_vlans
        native_vlan_id = self.native_vlan_id
        native_vlan_source = self.native_vlan_source
        facts = dict(self.facts)
        if base is not None:
            if description is None:
                description = base.description
                if "description" in base.facts:
                    facts["description"] = base.facts["description"]
            if enabled is None:
                enabled = base.enabled
                if "enabled" in base.facts:
                    facts["enabled"] = base.facts["enabled"]
            if switchport_mode is None:
                switchport_mode = base.switchport_mode
                if "switchport_mode" in base.facts:
                    facts["switchport_mode"] = base.facts["switchport_mode"]
            if not vlan_members and not all_vlans:
                vlan_members = base.vlan_members
                vlan_member_sources = base.vlan_member_sources
                all_vlans = base.all_vlans
            if native_vlan_id is None:
                native_vlan_id = base.native_vlan_id
                native_vlan_source = base.native_vlan_source

        vlan_ids_by_name = vlan_ids_by_name or {}
        vlan_ids: set[int] = set()
        vlan_names: list[str] = []
        for member in vlan_members:
            if member.isdigit() and _valid_vlan_id(int(member)):
                vlan_ids.add(int(member))
            else:
                vlan_names.append(member)
                if member in vlan_ids_by_name:
                    vlan_ids.add(vlan_ids_by_name[member])

        access_vlan: VlanReference | None = None
        allowed_vlans: VlanSet | None = None
        if vlan_member_sources and switchport_mode == "access" and len(vlan_members) == 1:
            member = vlan_members[0]
            access_vlan = VlanReference(
                vlan_id=(
                    int(member)
                    if member.isdigit() and _valid_vlan_id(int(member))
                    else vlan_ids_by_name.get(member)
                ),
                name=None if member.isdigit() else member,
                provenance=source_location(vlan_member_sources),
            )
        elif vlan_member_sources:
            allowed_vlans = VlanSet(
                vlan_ids=sorted(vlan_ids),
                vlan_names=list(dict.fromkeys(vlan_names)),
                all_vlans=all_vlans,
                provenance=source_location(vlan_member_sources),
            )

        native_vlan = None
        if native_vlan_id is not None and native_vlan_source is not None:
            native_vlan = VlanReference(
                vlan_id=native_vlan_id,
                provenance=source_location([native_vlan_source]),
            )
        return InterfaceConfig(
            name=self.name,
            unit=self.unit,
            description=description,
            enabled=enabled,
            addresses=self.addresses,
            switchport_mode=switchport_mode,
            access_vlan=access_vlan,
            native_vlan=native_vlan,
            allowed_vlans=allowed_vlans,
            provenance={key: source_location(value) for key, value in facts.items()},
        )


@dataclass
class _JunosVlan:
    name: str
    vlan_id: int | None = None
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self) -> VlanConfig:
        return VlanConfig(
            vlan_id=self.vlan_id,
            name=self.name,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _JunosAclRule:
    term: str
    action: Literal["permit", "deny"] | None = None
    protocol: str | None = None
    source_addresses: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    source_ports: list[str] = field(default_factory=list)
    destination_ports: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    source_lines: list[tuple[int, str]] = field(default_factory=list)

    def build(self) -> AclRule | None:
        if self.action is None:
            return None
        return AclRule(
            term=self.term,
            action=self.action,
            protocol=self.protocol,
            source_addresses=self.source_addresses,
            destination_addresses=self.destination_addresses,
            source_ports=self.source_ports,
            destination_ports=self.destination_ports,
            options=self.options,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _JunosAcl:
    name: str
    family: Literal["ipv4", "ipv6"]
    terms: dict[str, _JunosAclRule] = field(default_factory=dict)
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def ensure_term(self, term: str, number: int, raw_line: str) -> _JunosAclRule:
        if term not in self.terms:
            self.terms[term] = _JunosAclRule(term=term)
            self.terms[term].facts["term"].append((number, raw_line))
        return self.terms[term]


@dataclass
class _JunosPrefixList:
    name: str
    family: Literal["ipv4", "ipv6"]
    rules: list[PrefixListRule] = field(default_factory=list)
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self) -> PrefixListConfig:
        return PrefixListConfig(
            name=self.name,
            family=self.family,
            rules=self.rules,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _JunosStaticRoute:
    family: Literal["ipv4", "ipv6"]
    destination: str
    next_hop: str | None = None
    outgoing_interface: str | None = None
    preference: int | None = None
    discard: bool = False
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self) -> StaticRouteConfig:
        return StaticRouteConfig(
            family=self.family,
            destination=self.destination,
            next_hop=self.next_hop,
            outgoing_interface=self.outgoing_interface,
            preference=self.preference,
            discard=self.discard,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _JunosBgpNeighbor:
    address: str
    remote_as: int | None = None
    description: str | None = None
    update_source: str | None = None
    enabled: bool | None = None
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    source_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class _JunosBgpGroup:
    name: str
    peer_as: int | None = None
    session_type: Literal["internal", "external"] | None = None
    local_address: str | None = None
    enabled: bool | None = None
    neighbors: dict[str, _JunosBgpNeighbor] = field(default_factory=dict)
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def ensure_neighbor(
        self, address: str, number: int, raw_line: str
    ) -> _JunosBgpNeighbor:
        if address not in self.neighbors:
            neighbor = _JunosBgpNeighbor(address=address)
            neighbor.facts["address"].append((number, raw_line))
            self.neighbors[address] = neighbor
        return self.neighbors[address]


@dataclass
class _JunosOspfInterface:
    name: str
    area_id: str
    passive: bool | None = None
    cost: int | None = None
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self) -> OspfInterfaceConfig:
        return OspfInterfaceConfig(
            name=self.name,
            area_id=self.area_id,
            passive=self.passive,
            cost=self.cost,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


class JuniperJunosParser(VendorParser):
    """Parse a deliberately small, tested subset of JunOS syntax."""

    vendor = Vendor.JUNIPER
    platform = "junos"

    def parse(
        self,
        text: str,
        *,
        filename: str,
        collected_at: datetime | None = None,
    ) -> CanonicalConfig:
        state = _JunosState()
        context: list[str] = []

        for number, raw_line in enumerate(text.splitlines(), start=1):
            command = _strip_comment(raw_line).strip()
            if not command or command.startswith("##"):
                continue
            state.significant_count += 1

            if command.lower().startswith("set "):
                if not state.consume_set(command, number, raw_line):
                    state.add_unparsed(number, raw_line)
                continue

            if re.fullmatch(r"}[;]?", command):
                if context:
                    context.pop()
                continue

            if command.endswith("{"):
                block = command[:-1].strip()
                if state.consume_block(context, block, number, raw_line):
                    context.append(block)
                else:
                    state.add_unparsed(number, raw_line)
                    context.append(block)
                continue

            leaf = command[:-1].strip() if command.endswith(";") else command
            if not state.consume_leaf(context, leaf, number, raw_line):
                state.add_unparsed(number, raw_line)

        return state.build(text=text, filename=filename, collected_at=collected_at)


class _JunosState:
    def __init__(self) -> None:
        self.hostname: str | None = None
        self.aaa_enabled = False
        self.ssh_enabled = False
        self.telnet_enabled = False
        self.snmp_versions: set[str] = set()
        self.ntp_servers: list[str] = []
        self.syslog_servers: list[str] = []
        self.facts: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.interfaces: dict[tuple[str, str | None], _JunosInterface] = {}
        self.vlans: dict[str, _JunosVlan] = {}
        self.acls: dict[tuple[str, str], _JunosAcl] = {}
        self.prefix_lists: dict[tuple[str, str], _JunosPrefixList] = {}
        self.static_routes: dict[tuple[str, str], _JunosStaticRoute] = {}
        self.bgp_local_as: int | None = None
        self.bgp_router_id: str | None = None
        self.bgp_groups: dict[str, _JunosBgpGroup] = {}
        self.bgp_facts: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.bgp_source_lines: list[tuple[int, str]] = []
        self.bgp_seen = False
        self.ospf_seen = False
        self.ospf_interfaces: dict[str, _JunosOspfInterface] = {}
        self.ospf_facts: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.unparsed: list[UnparsedFragment] = []
        self.warnings: list[str] = []
        self.significant_count = 0

    def remember(self, fact: str, number: int, raw_line: str) -> None:
        self.facts[fact].append((number, raw_line))

    def add_unparsed(self, number: int, raw_line: str) -> None:
        self.unparsed.append(
            UnparsedFragment(
                raw_text=raw_line,
                location=source_location([(number, raw_line)], parser_confidence=0.0),
            )
        )

    def consume_set(self, command: str, number: int, raw_line: str) -> bool:
        try:
            tokens = shlex.split(command)
        except ValueError:
            return False
        lowered = [token.lower() for token in tokens]
        if lowered[:3] == ["set", "system", "host-name"] and len(tokens) >= 4:
            self.hostname = tokens[3]
            self.remember("hostname", number, raw_line)
        elif lowered[:4] == ["set", "system", "services", "ssh"]:
            self.ssh_enabled = True
            self.remember("ssh_enabled", number, raw_line)
        elif lowered[:4] == ["set", "system", "services", "telnet"]:
            self.telnet_enabled = True
            self.remember("telnet_enabled", number, raw_line)
        elif lowered[:3] == ["set", "system", "authentication-order"]:
            self.aaa_enabled = any(token in {"radius", "tacplus"} for token in lowered[3:])
            self.remember("aaa_enabled", number, raw_line)
        elif lowered[:3] in (
            ["set", "system", "radius-server"],
            ["set", "system", "tacplus-server"],
        ):
            self.aaa_enabled = True
            self.remember("aaa_enabled", number, raw_line)
        elif lowered[:4] == ["set", "system", "ntp", "server"] and len(tokens) >= 5:
            self.ntp_servers.append(tokens[4])
            self.remember("ntp_servers", number, raw_line)
        elif lowered[:4] == ["set", "system", "syslog", "host"] and len(tokens) >= 5:
            self.syslog_servers.append(tokens[4])
            self.remember("syslog_servers", number, raw_line)
        elif lowered[:3] == ["set", "snmp", "v3"]:
            self.snmp_versions.add("v3")
            self.remember("snmp_versions", number, raw_line)
        elif lowered[:3] == ["set", "snmp", "community"]:
            self.snmp_versions.update({"v1", "v2c"})
            self.remember("snmp_versions", number, raw_line)
        elif lowered[:2] == ["set", "interfaces"]:
            return self.consume_set_interface(tokens, number, raw_line)
        elif lowered[:2] == ["set", "vlans"]:
            return self.consume_set_vlan(tokens, number, raw_line)
        elif lowered[:2] == ["set", "firewall"]:
            return self.consume_set_firewall(tokens, number, raw_line)
        elif lowered[:3] == ["set", "policy-options", "prefix-list"]:
            return self.consume_set_prefix_list(tokens, number, raw_line)
        elif lowered[:4] == ["set", "routing-options", "static", "route"]:
            return self.consume_set_static_route(tokens, number, raw_line)
        elif lowered[:2] == ["set", "routing-options"]:
            return self.consume_set_routing_options(tokens, number, raw_line)
        elif lowered[:3] == ["set", "protocols", "bgp"]:
            return self.consume_set_bgp(tokens, number, raw_line)
        elif lowered[:3] == ["set", "protocols", "ospf"]:
            return self.consume_set_ospf(tokens, number, raw_line)
        else:
            return False
        return True

    def consume_set_firewall(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if (
            len(tokens) < 10
            or lowered[2] != "family"
            or lowered[4] != "filter"
            or lowered[6] != "term"
        ):
            return False
        family = _junos_family(tokens[3])
        if family is None:
            return False
        acl = self.ensure_acl(tokens[5], family, number, raw_line)
        term = acl.ensure_term(tokens[7], number, raw_line)
        term.source_lines.append((number, raw_line))
        if lowered[8] == "then" and len(tokens) == 10:
            action = _junos_acl_action(tokens[9])
            if action is None:
                return False
            term.action = action
            term.facts["action"].append((number, raw_line))
            return True
        if lowered[8] != "from" or len(tokens) < 11:
            return False
        return self.add_firewall_match(
            term, family, tokens[9], tokens[10:], number, raw_line
        )

    def consume_set_prefix_list(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        if len(tokens) != 5:
            return False
        return self.add_prefix_list_entry(tokens[3], tokens[4], number, raw_line)

    def consume_set_static_route(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        if len(tokens) < 6:
            return False
        route = self.ensure_static_route(tokens[4], number, raw_line)
        if route is None:
            return False
        return self.apply_static_route_tokens(route, tokens[5:], number, raw_line)

    def consume_set_routing_options(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if len(tokens) != 4:
            return False
        if lowered[2] == "autonomous-system":
            local_as = _parse_asn(tokens[3])
            if local_as is None:
                self.warnings.append(f"invalid BGP local AS at line {number}")
                return False
            self.bgp_local_as = local_as
            self.bgp_facts["local_as"].append((number, raw_line))
            return True
        if lowered[2] == "router-id":
            router_id = _parse_router_id(tokens[3])
            if router_id is None:
                self.warnings.append(f"invalid BGP router ID at line {number}")
                return False
            self.bgp_router_id = router_id
            self.bgp_facts["router_id"].append((number, raw_line))
            return True
        return False

    def consume_set_bgp(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if len(tokens) < 6 or lowered[3] != "group":
            return False
        self.bgp_seen = True
        self.bgp_source_lines.append((number, raw_line))
        group = self.ensure_bgp_group(tokens[4], number, raw_line)
        remainder = tokens[5:]
        if remainder[0].lower() == "neighbor":
            if len(remainder) < 2:
                return False
            neighbor = self.ensure_bgp_neighbor(
                group, remainder[1], number, raw_line
            )
            if neighbor is None:
                return False
            neighbor.source_lines.append((number, raw_line))
            if len(remainder) == 2:
                return True
            return self.apply_bgp_neighbor_tokens(
                neighbor, remainder[2:], number, raw_line
            )
        return self.apply_bgp_group_tokens(group, remainder, number, raw_line)

    def consume_set_ospf(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if (
            len(tokens) < 7
            or lowered[3] != "area"
            or lowered[5] != "interface"
        ):
            return False
        self.remember_ospf(number, raw_line)
        interface = self.ensure_ospf_interface(
            tokens[6], tokens[4], number, raw_line
        )
        if interface is None:
            return False
        if len(tokens) == 7:
            return True
        return self.apply_ospf_interface_tokens(
            interface, tokens[7:], number, raw_line
        )

    def consume_set_vlan(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        if len(tokens) != 5 or tokens[3].lower() != "vlan-id":
            return False
        vlan_id = _parse_vlan_id(tokens[4])
        if vlan_id is None:
            self.warnings.append(f"invalid VLAN identifier at line {number}")
            return False
        vlan = self.ensure_vlan(tokens[2], number, raw_line)
        vlan.vlan_id = vlan_id
        vlan.facts["vlan_id"].append((number, raw_line))
        return True

    def consume_set_interface(
        self, tokens: list[str], number: int, raw_line: str
    ) -> bool:
        if len(tokens) < 4:
            return False
        name = tokens[2]
        lowered = [token.lower() for token in tokens]
        remainder = lowered[3:]
        if remainder[0] == "description" and len(tokens) >= 5:
            interface = self.ensure_interface(name, None, number, raw_line)
            interface.description = " ".join(tokens[4:])
            interface.facts["description"].append((number, raw_line))
            return True
        if remainder == ["disable"]:
            interface = self.ensure_interface(name, None, number, raw_line)
            interface.enabled = False
            interface.facts["enabled"].append((number, raw_line))
            return True
        if len(remainder) < 3 or remainder[0] != "unit":
            return False

        unit = tokens[4]
        unit_remainder = lowered[5:]
        interface = self.ensure_interface(name, unit, number, raw_line)
        if unit_remainder and unit_remainder[0] == "description" and len(tokens) >= 7:
            interface.description = " ".join(tokens[6:])
            interface.facts["description"].append((number, raw_line))
            return True
        if unit_remainder == ["disable"]:
            interface.enabled = False
            interface.facts["enabled"].append((number, raw_line))
            return True
        if (
            len(unit_remainder) == 4
            and unit_remainder[0] == "family"
            and unit_remainder[2] == "address"
        ):
            family = _junos_family(unit_remainder[1])
            if family is None:
                return False
            return self.add_interface_address(
                interface, tokens[8], family, number, raw_line
            )
        if (
            len(unit_remainder) == 4
            and unit_remainder[:2] == ["family", "ethernet-switching"]
            and unit_remainder[2] in {"interface-mode", "port-mode"}
            and unit_remainder[3] in {"access", "trunk"}
        ):
            interface.switchport_mode = (
                "access" if unit_remainder[3] == "access" else "trunk"
            )
            interface.facts["switchport_mode"].append((number, raw_line))
            return True
        if (
            len(unit_remainder) == 4
            and unit_remainder[:3]
            == ["family", "ethernet-switching", "native-vlan-id"]
        ):
            vlan_id = _parse_vlan_id(tokens[8])
            if vlan_id is None:
                self.warnings.append(f"invalid native VLAN at line {number}")
                return False
            interface.native_vlan_id = vlan_id
            interface.native_vlan_source = (number, raw_line)
            return True
        if (
            len(unit_remainder) >= 5
            and unit_remainder[:4]
            == ["family", "ethernet-switching", "vlan", "members"]
        ):
            return self.add_vlan_members(interface, tokens[9:], number, raw_line)
        return False

    def consume_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        name = block.split()[0].lower()
        context_names = [item.split()[0].lower() for item in context]
        if name == "firewall" and not context:
            return True
        if "firewall" in context_names:
            return self.consume_firewall_block(context, block, number, raw_line)
        if name == "policy-options" and not context:
            return True
        if "policy-options" in context_names:
            return self.consume_policy_block(context, block)
        if name == "routing-options" and not context:
            return True
        if "routing-options" in context_names:
            return self.consume_routing_block(context, block, number, raw_line)
        if name == "protocols" and not context:
            return True
        if "protocols" in context_names:
            if name == "bgp" and context[-1].split()[0].lower() == "protocols":
                self.bgp_seen = True
                self.bgp_source_lines.append((number, raw_line))
                return True
            if "bgp" in context_names:
                return self.consume_bgp_block(context, block, number, raw_line)
            if name == "ospf" and context[-1].split()[0].lower() == "protocols":
                self.remember_ospf(number, raw_line)
                return True
            if "ospf" in context_names:
                return self.consume_ospf_block(context, block, number, raw_line)
            return False
        if name == "interfaces" and not context:
            return True
        if "interfaces" in context_names:
            return self.consume_interface_block(context, block, number, raw_line)
        if name == "vlans" and not context:
            return True
        if "vlans" in context_names:
            return self.consume_vlan_block(context, block, number, raw_line)
        if name not in _SAFE_BLOCKS:
            return False
        if name in {"radius-server", "tacplus-server"} and "system" in context_names:
            self.aaa_enabled = True
            self.remember("aaa_enabled", number, raw_line)
        elif name == "host" and "syslog" in context_names:
            parts = block.split()
            if len(parts) >= 2:
                self.syslog_servers.append(parts[1])
                self.remember("syslog_servers", number, raw_line)
        elif name == "v3" and "snmp" in context_names:
            self.snmp_versions.add("v3")
            self.remember("snmp_versions", number, raw_line)
        elif name == "community" and "snmp" in context_names:
            self.snmp_versions.update({"v1", "v2c"})
            self.remember("snmp_versions", number, raw_line)
        return True

    def consume_firewall_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        parts = block.split()
        name = parts[0].lower()
        family, filter_name, term_name = _firewall_context(context)
        if name == "family" and len(parts) == 2:
            return _junos_family(parts[1]) is not None
        if name == "filter" and len(parts) == 2 and family is not None:
            self.ensure_acl(parts[1], family, number, raw_line)
            return True
        if (
            name == "term"
            and len(parts) == 2
            and family is not None
            and filter_name is not None
        ):
            acl = self.ensure_acl(filter_name, family, number, raw_line)
            acl.ensure_term(parts[1], number, raw_line)
            return True
        if term_name is not None and name in {
            "from",
            "then",
            "source-address",
            "destination-address",
            "source-port",
            "destination-port",
        }:
            return True
        return False

    def consume_policy_block(self, context: list[str], block: str) -> bool:
        parts = block.split()
        return (
            len(parts) == 2
            and parts[0].lower() == "prefix-list"
            and context[-1].split()[0].lower() == "policy-options"
        )

    def consume_routing_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        parts = block.split()
        if (
            len(parts) == 1
            and parts[0].lower() == "static"
            and context[-1].split()[0].lower() == "routing-options"
        ):
            return True
        if (
            len(parts) == 2
            and parts[0].lower() == "route"
            and "static" in [item.split()[0].lower() for item in context]
        ):
            return self.ensure_static_route(parts[1], number, raw_line) is not None
        return False

    def consume_bgp_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        parts = block.split()
        group_name, _ = _bgp_context(context)
        if len(parts) == 2 and parts[0].lower() == "group" and group_name is None:
            self.ensure_bgp_group(parts[1], number, raw_line)
            self.bgp_source_lines.append((number, raw_line))
            return True
        if (
            len(parts) == 2
            and parts[0].lower() == "neighbor"
            and group_name is not None
        ):
            group = self.ensure_bgp_group(group_name, number, raw_line)
            neighbor = self.ensure_bgp_neighbor(group, parts[1], number, raw_line)
            if neighbor is None:
                return False
            neighbor.source_lines.append((number, raw_line))
            self.bgp_source_lines.append((number, raw_line))
            return True
        return False

    def consume_ospf_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        parts = block.split()
        area_id, interface_name = _ospf_context(context)
        if len(parts) == 2 and parts[0].lower() == "area" and area_id is None:
            if _normalize_ospf_area_id(parts[1]) is None:
                self.warnings.append(f"invalid OSPF area at line {number}")
                return False
            self.remember_ospf(number, raw_line)
            return True
        if (
            len(parts) == 2
            and parts[0].lower() == "interface"
            and area_id is not None
            and interface_name is None
        ):
            interface = self.ensure_ospf_interface(
                parts[1], area_id, number, raw_line
            )
            if interface is None:
                return False
            self.remember_ospf(number, raw_line)
            return True
        return False

    def consume_interface_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        interface_name, unit, _ = _interface_context(context)
        parts = block.split()
        name = parts[0].lower()
        if context and context[-1].split()[0].lower() == "interfaces":
            self.ensure_interface(block, None, number, raw_line)
            return True
        if name == "unit" and interface_name is not None and len(parts) >= 2:
            self.ensure_interface(interface_name, parts[1], number, raw_line)
            return True
        if name == "family" and interface_name is not None and len(parts) >= 2:
            return _junos_family(parts[1]) is not None or parts[1].lower() == "ethernet-switching"
        if name in {"inet", "inet6"} and interface_name is not None:
            return True
        if name == "vlan" and interface_name is not None:
            return _interface_family_name(context) == "ethernet-switching"
        if name == "address" and interface_name is not None and len(parts) >= 2:
            family = _family_from_context(context)
            if family is None:
                return False
            interface = self.ensure_interface(interface_name, unit, number, raw_line)
            return self.add_interface_address(
                interface, parts[1], family, number, raw_line
            )
        return False

    def consume_vlan_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        if context and context[-1].split()[0].lower() == "vlans":
            self.ensure_vlan(block, number, raw_line)
            return True
        return False

    def consume_leaf(
        self, context: list[str], leaf: str, number: int, raw_line: str
    ) -> bool:
        context_names = [item.split()[0].lower() for item in context]
        tokens = leaf.split()
        if not tokens:
            return True
        lowered = [token.lower() for token in tokens]

        if "interfaces" in context_names:
            return self.consume_interface_leaf(context, leaf, number, raw_line)
        if "vlans" in context_names:
            return self.consume_vlan_leaf(context, leaf, number, raw_line)
        if "firewall" in context_names:
            return self.consume_firewall_leaf(context, leaf, number, raw_line)
        if "policy-options" in context_names:
            prefix_list_name = _prefix_list_context(context)
            if prefix_list_name is None:
                return False
            return self.add_prefix_list_entry(
                prefix_list_name, leaf, number, raw_line
            )
        if "routing-options" in context_names:
            return self.consume_routing_options_leaf(context, tokens, number, raw_line)
        if "bgp" in context_names:
            return self.consume_bgp_leaf(context, tokens, number, raw_line)
        if "ospf" in context_names:
            return self.consume_ospf_leaf(context, tokens, number, raw_line)

        if lowered[0] == "host-name" and "system" in context_names and len(tokens) >= 2:
            self.hostname = tokens[1]
            self.remember("hostname", number, raw_line)
        elif lowered == ["ssh"] and "services" in context_names:
            self.ssh_enabled = True
            self.remember("ssh_enabled", number, raw_line)
        elif lowered == ["telnet"] and "services" in context_names:
            self.telnet_enabled = True
            self.remember("telnet_enabled", number, raw_line)
        elif lowered[0] == "authentication-order" and "system" in context_names:
            self.aaa_enabled = any(token in {"radius", "tacplus"} for token in lowered[1:])
            self.remember("aaa_enabled", number, raw_line)
        elif lowered[0] == "server" and "ntp" in context_names and len(tokens) >= 2:
            self.ntp_servers.append(tokens[1])
            self.remember("ntp_servers", number, raw_line)
        elif lowered[0] in {"authorization", "description"} and "community" in context_names:
            return True
        elif lowered[0] in {"any", "interactive-commands"} and "host" in context_names:
            return True
        else:
            return False
        return True

    def consume_vlan_leaf(
        self, context: list[str], leaf: str, number: int, raw_line: str
    ) -> bool:
        vlan_name = _vlan_context(context)
        tokens = leaf.split()
        if vlan_name is None or len(tokens) != 2 or tokens[0].lower() != "vlan-id":
            return False
        vlan_id = _parse_vlan_id(tokens[1])
        if vlan_id is None:
            self.warnings.append(f"invalid VLAN identifier at line {number}")
            return False
        vlan = self.ensure_vlan(vlan_name, number, raw_line)
        vlan.vlan_id = vlan_id
        vlan.facts["vlan_id"].append((number, raw_line))
        return True

    def consume_interface_leaf(
        self, context: list[str], leaf: str, number: int, raw_line: str
    ) -> bool:
        interface_name, unit, family = _interface_context(context)
        family_name = _interface_family_name(context)
        if interface_name is None:
            return False
        interface = self.ensure_interface(interface_name, unit, number, raw_line)
        lowered = leaf.lower()
        if lowered.startswith("description "):
            interface.description = _unquote(leaf.split(maxsplit=1)[1])
            interface.facts["description"].append((number, raw_line))
            return True
        if lowered == "disable":
            interface.enabled = False
            interface.facts["enabled"].append((number, raw_line))
            return True
        if lowered.startswith("address ") and family is not None:
            address_tokens = leaf.split()
            if len(address_tokens) != 2:
                return False
            value = address_tokens[1]
            return self.add_interface_address(
                interface, value, family, number, raw_line
            )
        tokens = leaf.split()
        lowered_tokens = [token.lower() for token in tokens]
        if (
            family_name == "ethernet-switching"
            and len(lowered_tokens) == 2
            and lowered_tokens[0] in {"interface-mode", "port-mode"}
            and lowered_tokens[1] in {"access", "trunk"}
        ):
            interface.switchport_mode = (
                "access" if lowered_tokens[1] == "access" else "trunk"
            )
            interface.facts["switchport_mode"].append((number, raw_line))
            return True
        if (
            family_name == "ethernet-switching"
            and len(lowered_tokens) == 2
            and lowered_tokens[0] == "native-vlan-id"
        ):
            vlan_id = _parse_vlan_id(tokens[1])
            if vlan_id is None:
                self.warnings.append(f"invalid native VLAN at line {number}")
                return False
            interface.native_vlan_id = vlan_id
            interface.native_vlan_source = (number, raw_line)
            return True
        if (
            family_name == "ethernet-switching"
            and lowered_tokens
            and lowered_tokens[0] == "members"
        ):
            return self.add_vlan_members(interface, tokens[1:], number, raw_line)
        return False

    def consume_firewall_leaf(
        self, context: list[str], leaf: str, number: int, raw_line: str
    ) -> bool:
        family, filter_name, term_name = _firewall_context(context)
        if family is None or filter_name is None or term_name is None:
            return False
        acl = self.ensure_acl(filter_name, family, number, raw_line)
        term = acl.ensure_term(term_name, number, raw_line)
        term.source_lines.append((number, raw_line))
        tokens = leaf.split()
        if not tokens:
            return False
        parent = context[-1].split()[0].lower()
        if parent == "then":
            action = _junos_acl_action(tokens[0])
            if action is None or len(tokens) != 1:
                return False
            term.action = action
            term.facts["action"].append((number, raw_line))
            return True
        if tokens[0].lower() == "then" and len(tokens) == 2:
            action = _junos_acl_action(tokens[1])
            if action is None:
                return False
            term.action = action
            term.facts["action"].append((number, raw_line))
            return True
        if parent in {
            "source-address",
            "destination-address",
            "source-port",
            "destination-port",
        }:
            return self.add_firewall_match(
                term, family, parent, tokens, number, raw_line
            )
        return self.add_firewall_match(
            term, family, tokens[0], tokens[1:], number, raw_line
        )

    def ensure_acl(
        self,
        name: str,
        family: Literal["ipv4", "ipv6"],
        number: int,
        raw_line: str,
    ) -> _JunosAcl:
        key = (family, name)
        if key not in self.acls:
            acl = _JunosAcl(name=name, family=family)
            acl.facts["name"].append((number, raw_line))
            self.acls[key] = acl
        return self.acls[key]

    def add_firewall_match(
        self,
        term: _JunosAclRule,
        family: Literal["ipv4", "ipv6"],
        field_name: str,
        raw_values: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        name = field_name.lower()
        values = [value.strip("[],") for value in raw_values if value.strip("[],")]
        if name == "protocol" and len(values) == 1:
            term.protocol = values[0].lower()
            term.facts["protocol"].append((number, raw_line))
            return True
        if name in {"source-address", "destination-address"} and values:
            networks: list[str] = []
            for value in values:
                if value.lower() == "any":
                    networks.append("any")
                    continue
                try:
                    network = ip_network(value, strict=False)
                except ValueError:
                    self.warnings.append(f"invalid firewall address at line {number}")
                    return False
                if network.version != (4 if family == "ipv4" else 6):
                    self.warnings.append(
                        f"firewall address family mismatch at line {number}"
                    )
                    return False
                networks.append(str(network))
            target = (
                term.source_addresses
                if name == "source-address"
                else term.destination_addresses
            )
            for normalized_network in networks:
                if normalized_network not in target:
                    target.append(normalized_network)
            term.facts[name.replace("-", "_")].append((number, raw_line))
            return True
        if name in {"source-port", "destination-port"} and values:
            target_ports = (
                term.source_ports if name == "source-port" else term.destination_ports
            )
            for value in values:
                if value not in target_ports:
                    target_ports.append(value)
            term.facts[name.replace("-", "_")].append((number, raw_line))
            return True
        if name in {"tcp-established", "is-fragment", "first-fragment"} and not values:
            term.options.append(name)
            term.facts["options"].append((number, raw_line))
            return True
        if name == "icmp-type" and values:
            term.options.extend(f"icmp-type:{value}" for value in values)
            term.facts["options"].append((number, raw_line))
            return True
        return False

    def add_prefix_list_entry(
        self, name: str, value: str, number: int, raw_line: str
    ) -> bool:
        tokens = value.split()
        if len(tokens) != 1:
            return False
        try:
            network = ip_network(tokens[0], strict=False)
        except ValueError:
            self.warnings.append(f"invalid prefix-list entry at line {number}")
            return False
        family: Literal["ipv4", "ipv6"] = "ipv4" if network.version == 4 else "ipv6"
        key = (family, name)
        if key not in self.prefix_lists:
            prefix_list = _JunosPrefixList(name=name, family=family)
            prefix_list.facts["name"].append((number, raw_line))
            self.prefix_lists[key] = prefix_list
        self.prefix_lists[key].rules.append(
            PrefixListRule(
                prefix=str(network),
                provenance=source_location([(number, raw_line)]),
            )
        )
        return True

    def consume_routing_options_leaf(
        self,
        context: list[str],
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        context_names = [item.split()[0].lower() for item in context]
        if "static" in context_names:
            return self.consume_static_route_leaf(context, tokens, number, raw_line)
        lowered = [token.lower() for token in tokens]
        if lowered[:1] == ["autonomous-system"] and len(tokens) == 2:
            local_as = _parse_asn(tokens[1])
            if local_as is None:
                self.warnings.append(f"invalid BGP local AS at line {number}")
                return False
            self.bgp_local_as = local_as
            self.bgp_facts["local_as"].append((number, raw_line))
            return True
        if lowered[:1] == ["router-id"] and len(tokens) == 2:
            router_id = _parse_router_id(tokens[1])
            if router_id is None:
                self.warnings.append(f"invalid BGP router ID at line {number}")
                return False
            self.bgp_router_id = router_id
            self.bgp_facts["router_id"].append((number, raw_line))
            return True
        return False

    def consume_bgp_leaf(
        self,
        context: list[str],
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        group_name, neighbor_address = _bgp_context(context)
        if group_name is None:
            return False
        group = self.ensure_bgp_group(group_name, number, raw_line)
        if neighbor_address is not None:
            neighbor = self.ensure_bgp_neighbor(
                group, neighbor_address, number, raw_line
            )
            if neighbor is None:
                return False
            neighbor.source_lines.append((number, raw_line))
            consumed = self.apply_bgp_neighbor_tokens(
                neighbor, tokens, number, raw_line
            )
        elif tokens[0].lower() == "neighbor" and len(tokens) >= 2:
            neighbor = self.ensure_bgp_neighbor(group, tokens[1], number, raw_line)
            if neighbor is None:
                return False
            neighbor.source_lines.append((number, raw_line))
            consumed = len(tokens) == 2 or self.apply_bgp_neighbor_tokens(
                neighbor, tokens[2:], number, raw_line
            )
        else:
            consumed = self.apply_bgp_group_tokens(
                group, tokens, number, raw_line
            )
        if consumed:
            self.bgp_source_lines.append((number, raw_line))
        return consumed

    def ensure_bgp_group(
        self, name: str, number: int, raw_line: str
    ) -> _JunosBgpGroup:
        if name not in self.bgp_groups:
            group = _JunosBgpGroup(name=name)
            group.facts["name"].append((number, raw_line))
            self.bgp_groups[name] = group
        return self.bgp_groups[name]

    def ensure_bgp_neighbor(
        self,
        group: _JunosBgpGroup,
        value: str,
        number: int,
        raw_line: str,
    ) -> _JunosBgpNeighbor | None:
        try:
            address = str(ip_address(value))
        except ValueError:
            self.warnings.append(f"invalid BGP neighbor address at line {number}")
            return None
        return group.ensure_neighbor(address, number, raw_line)

    def apply_bgp_group_tokens(
        self,
        group: _JunosBgpGroup,
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if lowered[:1] == ["type"] and len(tokens) == 2:
            if lowered[1] not in {"internal", "external"}:
                return False
            group.session_type = (
                "internal" if lowered[1] == "internal" else "external"
            )
            group.facts["session_type"].append((number, raw_line))
            return True
        if lowered[:1] == ["peer-as"] and len(tokens) == 2:
            peer_as = _parse_asn(tokens[1])
            if peer_as is None:
                self.warnings.append(f"invalid BGP peer AS at line {number}")
                return False
            group.peer_as = peer_as
            group.facts["remote_as"].append((number, raw_line))
            return True
        if lowered[:1] == ["local-address"] and len(tokens) == 2:
            local_address = _parse_ip_address(tokens[1])
            if local_address is None:
                self.warnings.append(f"invalid BGP local address at line {number}")
                return False
            group.local_address = local_address
            group.facts["update_source"].append((number, raw_line))
            return True
        if lowered == ["shutdown"]:
            group.enabled = False
            group.facts["enabled"].append((number, raw_line))
            return True
        return False

    def apply_bgp_neighbor_tokens(
        self,
        neighbor: _JunosBgpNeighbor,
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if lowered[:1] == ["peer-as"] and len(tokens) == 2:
            remote_as = _parse_asn(tokens[1])
            if remote_as is None:
                self.warnings.append(f"invalid BGP peer AS at line {number}")
                return False
            neighbor.remote_as = remote_as
            neighbor.facts["remote_as"].append((number, raw_line))
            return True
        if lowered[:1] == ["description"] and len(tokens) >= 2:
            neighbor.description = _unquote(" ".join(tokens[1:]))
            neighbor.facts["description"].append((number, raw_line))
            return True
        if lowered[:1] == ["local-address"] and len(tokens) == 2:
            local_address = _parse_ip_address(tokens[1])
            if local_address is None:
                self.warnings.append(f"invalid BGP local address at line {number}")
                return False
            neighbor.update_source = local_address
            neighbor.facts["update_source"].append((number, raw_line))
            return True
        if lowered == ["shutdown"]:
            neighbor.enabled = False
            neighbor.facts["enabled"].append((number, raw_line))
            return True
        return False

    def remember_ospf(self, number: int, raw_line: str) -> None:
        if not self.ospf_seen:
            self.ospf_facts["process_id"].append((number, raw_line))
        self.ospf_seen = True

    def ensure_ospf_interface(
        self,
        name: str,
        area_value: str,
        number: int,
        raw_line: str,
    ) -> _JunosOspfInterface | None:
        area_id = _normalize_ospf_area_id(area_value)
        if area_id is None:
            self.warnings.append(f"invalid OSPF area at line {number}")
            return None
        if name in self.ospf_interfaces:
            interface = self.ospf_interfaces[name]
            if interface.area_id != area_id:
                self.warnings.append(
                    f"OSPF interface {name} is configured in multiple areas"
                )
                return None
            return interface
        interface = _JunosOspfInterface(name=name, area_id=area_id)
        interface.facts["name"].append((number, raw_line))
        interface.facts["area_id"].append((number, raw_line))
        self.ospf_interfaces[name] = interface
        return interface

    def apply_ospf_interface_tokens(
        self,
        interface: _JunosOspfInterface,
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if lowered == ["passive"]:
            interface.passive = True
            interface.facts["passive"].append((number, raw_line))
            return True
        if lowered[:1] == ["metric"] and len(tokens) == 2:
            if not tokens[1].isdigit() or not 1 <= int(tokens[1]) <= 65_535:
                self.warnings.append(f"invalid OSPF metric at line {number}")
                return False
            interface.cost = int(tokens[1])
            interface.facts["cost"].append((number, raw_line))
            return True
        return False

    def consume_ospf_leaf(
        self,
        context: list[str],
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        area_id, interface_name = _ospf_context(context)
        if area_id is None:
            return False
        if interface_name is not None:
            interface = self.ensure_ospf_interface(
                interface_name, area_id, number, raw_line
            )
            if interface is None:
                return False
            consumed = self.apply_ospf_interface_tokens(
                interface, tokens, number, raw_line
            )
        elif len(tokens) >= 2 and tokens[0].lower() == "interface":
            interface = self.ensure_ospf_interface(
                tokens[1], area_id, number, raw_line
            )
            if interface is None:
                return False
            consumed = len(tokens) == 2 or self.apply_ospf_interface_tokens(
                interface, tokens[2:], number, raw_line
            )
        else:
            return False
        if consumed:
            self.remember_ospf(number, raw_line)
        return consumed

    def consume_static_route_leaf(
        self,
        context: list[str],
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        destination = _static_route_context(context)
        if destination is not None:
            route = self.ensure_static_route(destination, number, raw_line)
            if route is None:
                return False
            return self.apply_static_route_tokens(route, tokens, number, raw_line)
        context_names = [item.split()[0].lower() for item in context]
        if "static" not in context_names or len(tokens) < 3 or tokens[0].lower() != "route":
            return False
        route = self.ensure_static_route(tokens[1], number, raw_line)
        if route is None:
            return False
        return self.apply_static_route_tokens(route, tokens[2:], number, raw_line)

    def ensure_static_route(
        self, destination: str, number: int, raw_line: str
    ) -> _JunosStaticRoute | None:
        try:
            network = ip_network(destination, strict=False)
        except ValueError:
            self.warnings.append(f"invalid static route at line {number}")
            return None
        family: Literal["ipv4", "ipv6"] = "ipv4" if network.version == 4 else "ipv6"
        key = (family, str(network))
        if key not in self.static_routes:
            route = _JunosStaticRoute(family=family, destination=str(network))
            route.facts["destination"].append((number, raw_line))
            self.static_routes[key] = route
        return self.static_routes[key]

    def apply_static_route_tokens(
        self,
        route: _JunosStaticRoute,
        tokens: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        lowered = [token.lower() for token in tokens]
        if lowered[:1] == ["next-hop"] and len(tokens) == 2:
            if route.discard:
                return False
            value = tokens[1]
            try:
                parsed = ip_address(value)
            except ValueError:
                if value[:1].isdigit():
                    self.warnings.append(f"invalid static route next hop at line {number}")
                    return False
                if route.next_hop is not None:
                    return False
                if route.outgoing_interface not in {None, value}:
                    return False
                route.outgoing_interface = value
                route.facts["outgoing_interface"].append((number, raw_line))
                return True
            if parsed.version != (4 if route.family == "ipv4" else 6):
                self.warnings.append(f"static route family mismatch at line {number}")
                return False
            normalized = str(parsed)
            if route.outgoing_interface is not None:
                return False
            if route.next_hop not in {None, normalized}:
                return False
            route.next_hop = normalized
            route.facts["next_hop"].append((number, raw_line))
            return True
        if lowered in (["discard"], ["reject"]):
            if route.next_hop is not None or route.outgoing_interface is not None:
                return False
            route.discard = True
            route.facts["discard"].append((number, raw_line))
            return True
        if lowered[:1] == ["preference"] and len(tokens) == 2:
            if not tokens[1].isdigit() or int(tokens[1]) > 255:
                self.warnings.append(f"invalid static route preference at line {number}")
                return False
            route.preference = int(tokens[1])
            route.facts["preference"].append((number, raw_line))
            return True
        return False

    def ensure_interface(
        self, name: str, unit: str | None, number: int, raw_line: str
    ) -> _JunosInterface:
        key = (name, unit)
        if key not in self.interfaces:
            interface = _JunosInterface(name=name, unit=unit)
            interface.facts["name"].append((number, raw_line))
            self.interfaces[key] = interface
        return self.interfaces[key]

    def ensure_vlan(self, name: str, number: int, raw_line: str) -> _JunosVlan:
        if name not in self.vlans:
            vlan = _JunosVlan(name=name)
            vlan.facts["name"].append((number, raw_line))
            self.vlans[name] = vlan
        return self.vlans[name]

    def add_vlan_members(
        self,
        interface: _JunosInterface,
        raw_members: list[str],
        number: int,
        raw_line: str,
    ) -> bool:
        members = [
            token.strip("[],")
            for token in raw_members
            if token.strip("[],")
        ]
        if not members:
            return False
        if "all" in [member.lower() for member in members]:
            if len(members) != 1:
                return False
            interface.all_vlans = True
            interface.vlan_member_sources.append((number, raw_line))
            return True
        for member in members:
            if member.isdigit() and not _valid_vlan_id(int(member)):
                self.warnings.append(f"invalid VLAN member at line {number}")
                return False
        for member in members:
            if member not in interface.vlan_members:
                interface.vlan_members.append(member)
        interface.vlan_member_sources.append((number, raw_line))
        return True

    def add_interface_address(
        self,
        interface: _JunosInterface,
        value: str,
        family: Literal["ipv4", "ipv6"],
        number: int,
        raw_line: str,
    ) -> bool:
        try:
            parsed = ip_interface(value)
        except ValueError:
            self.warnings.append(f"invalid {family} interface address at line {number}")
            return False
        expected_version = 4 if family == "ipv4" else 6
        if parsed.version != expected_version:
            self.warnings.append(f"invalid {family} interface address at line {number}")
            return False
        interface.addresses.append(
            InterfaceAddress(
                address=str(parsed),
                family=family,
                provenance=source_location([(number, raw_line)]),
            )
        )
        return True

    def build_interfaces(self) -> list[InterfaceConfig]:
        result: list[InterfaceConfig] = []
        vlan_ids_by_name = {
            name: vlan.vlan_id
            for name, vlan in self.vlans.items()
            if vlan.vlan_id is not None
        }
        names_with_units = {
            name for name, unit in self.interfaces if unit is not None
        }
        for (name, unit), interface in self.interfaces.items():
            base = self.interfaces.get((name, None))
            if unit is None and name in names_with_units and not interface.addresses:
                continue
            result.append(
                interface.build(
                    base if unit is not None else None,
                    vlan_ids_by_name=vlan_ids_by_name,
                )
            )
        return result

    def build_acls(self) -> list[AclConfig]:
        result: list[AclConfig] = []
        for acl in self.acls.values():
            rules: list[AclRule] = []
            for term in acl.terms.values():
                rule = term.build()
                if rule is None:
                    self.warnings.append(
                        f"firewall term {acl.name}/{term.term} has no supported action"
                    )
                    known_lines = {
                        fragment.location.source_lines[0] for fragment in self.unparsed
                    }
                    for number, raw_line in term.source_lines:
                        if number not in known_lines:
                            self.add_unparsed(number, raw_line)
                    continue
                rules.append(rule)
            result.append(
                AclConfig(
                    name=acl.name,
                    family=acl.family,
                    kind="firewall_filter",
                    rules=rules,
                    provenance={
                        key: source_location(value) for key, value in acl.facts.items()
                    },
                )
            )
        return result

    def build_static_routes(self) -> list[StaticRouteConfig]:
        result: list[StaticRouteConfig] = []
        for route in self.static_routes.values():
            try:
                result.append(route.build())
            except ValueError:
                self.warnings.append(
                    f"static route {route.destination} has no supported forwarding target"
                )
        return result

    def preserve_unparsed_lines(self, lines: list[tuple[int, str]]) -> None:
        known_lines = {
            fragment.location.source_lines[0] for fragment in self.unparsed
        }
        for number, raw_line in lines:
            if number not in known_lines:
                self.add_unparsed(number, raw_line)
                known_lines.add(number)

    def build_bgp(self) -> BgpConfig | None:
        if not self.bgp_seen:
            return None
        if self.bgp_local_as is None:
            self.warnings.append("BGP is configured without a valid local AS")
            self.preserve_unparsed_lines(self.bgp_source_lines)
            return None

        neighbors: list[BgpNeighborConfig] = []
        seen_addresses: set[str] = set()
        for group in self.bgp_groups.values():
            for neighbor in group.neighbors.values():
                remote_as = neighbor.remote_as or group.peer_as
                if remote_as is None and group.session_type == "internal":
                    remote_as = self.bgp_local_as
                if remote_as is None:
                    self.warnings.append(
                        f"BGP neighbor {neighbor.address} has no valid remote AS"
                    )
                    self.preserve_unparsed_lines(neighbor.source_lines)
                    continue
                if neighbor.address in seen_addresses:
                    self.warnings.append(
                        f"BGP neighbor {neighbor.address} is configured in multiple groups"
                    )
                    self.preserve_unparsed_lines(neighbor.source_lines)
                    continue

                facts = dict(neighbor.facts)
                if "name" in group.facts:
                    facts["group"] = group.facts["name"]
                if "remote_as" not in facts and "remote_as" in group.facts:
                    facts["remote_as"] = group.facts["remote_as"]
                if "update_source" not in facts and "update_source" in group.facts:
                    facts["update_source"] = group.facts["update_source"]
                if "enabled" not in facts and "enabled" in group.facts:
                    facts["enabled"] = group.facts["enabled"]
                if "session_type" in group.facts:
                    facts["session_type"] = group.facts["session_type"]

                session_type = group.session_type
                if session_type is None:
                    session_type = (
                        "internal"
                        if remote_as == self.bgp_local_as
                        else "external"
                    )
                family: Literal["ipv4", "ipv6"] = (
                    "ipv4" if ip_address(neighbor.address).version == 4 else "ipv6"
                )
                neighbors.append(
                    BgpNeighborConfig(
                        address=neighbor.address,
                        family=family,
                        remote_as=remote_as,
                        group=group.name,
                        description=neighbor.description,
                        session_type=session_type,
                        update_source=neighbor.update_source or group.local_address,
                        enabled=(
                            neighbor.enabled
                            if neighbor.enabled is not None
                            else group.enabled
                        ),
                        provenance={
                            key: source_location(value) for key, value in facts.items()
                        },
                    )
                )
                seen_addresses.add(neighbor.address)
        return BgpConfig(
            local_as=self.bgp_local_as,
            router_id=self.bgp_router_id,
            neighbors=neighbors,
            provenance={
                key: source_location(value) for key, value in self.bgp_facts.items()
            },
        )

    def build_ospf(self) -> list[OspfProcessConfig]:
        if not self.ospf_seen:
            return []
        facts = dict(self.ospf_facts)
        if "router_id" in self.bgp_facts:
            facts["router_id"] = self.bgp_facts["router_id"]
        return [
            OspfProcessConfig(
                process_id="default",
                router_id=self.bgp_router_id,
                interfaces=[
                    interface.build() for interface in self.ospf_interfaces.values()
                ],
                provenance={
                    key: source_location(value) for key, value in facts.items()
                },
            )
        ]

    def build(
        self, *, text: str, filename: str, collected_at: datetime | None
    ) -> CanonicalConfig:
        acls = self.build_acls()
        static_routes = self.build_static_routes()
        bgp = self.build_bgp()
        ospf = self.build_ospf()
        warnings = list(self.warnings)
        if self.hostname is None:
            warnings.append("hostname was not found")
        device_provenance = {
            key: source_location(value) for key, value in self.facts.items() if key == "hostname"
        }
        management_provenance = {
            key: source_location(value) for key, value in self.facts.items() if key != "hostname"
        }
        return CanonicalConfig(
            source=config_source(text, filename, collected_at),
            device=DeviceInfo(
                hostname=self.hostname,
                vendor=Vendor.JUNIPER,
                platform="junos",
                provenance=device_provenance,
            ),
            management=ManagementConfig(
                ssh_enabled=self.ssh_enabled,
                telnet_enabled=self.telnet_enabled,
                aaa_enabled=self.aaa_enabled,
                snmp_versions=[
                    version for version in ("v1", "v2c", "v3") if version in self.snmp_versions
                ],
                ntp_servers=list(dict.fromkeys(self.ntp_servers)),
                syslog_servers=list(dict.fromkeys(self.syslog_servers)),
                provenance=management_provenance,
            ),
            interfaces=self.build_interfaces(),
            vlans=[vlan.build() for vlan in self.vlans.values()],
            acls=acls,
            prefix_lists=[
                prefix_list.build() for prefix_list in self.prefix_lists.values()
            ],
            static_routes=static_routes,
            bgp=bgp,
            ospf=ospf,
            unparsed_fragments=self.unparsed,
            parse_warnings=warnings,
            parser_confidence=_overall_confidence(
                self.significant_count, len(self.unparsed)
            ),
        )


def _interface_context(
    context: list[str],
) -> tuple[str | None, str | None, Literal["ipv4", "ipv6"] | None]:
    names = [item.split()[0].lower() for item in context]
    if "interfaces" not in names:
        return None, None, None
    index = names.index("interfaces")
    if len(context) <= index + 1:
        return None, None, None
    interface_name = context[index + 1]
    unit: str | None = None
    family: Literal["ipv4", "ipv6"] | None = None
    for item in context[index + 2 :]:
        parts = item.split()
        lowered = [part.lower() for part in parts]
        if lowered and lowered[0] == "unit" and len(parts) >= 2:
            unit = parts[1]
        elif lowered and lowered[0] == "family" and len(parts) >= 2:
            family = _junos_family(parts[1])
        elif lowered and lowered[0] in {"inet", "inet6"}:
            family = _junos_family(parts[0])
    return interface_name, unit, family


def _family_from_context(
    context: list[str],
) -> Literal["ipv4", "ipv6"] | None:
    return _interface_context(context)[2]


def _interface_family_name(context: list[str]) -> str | None:
    names = [item.split()[0].lower() for item in context]
    if "interfaces" not in names:
        return None
    index = names.index("interfaces")
    for item in context[index + 2 :]:
        parts = item.split()
        if parts and parts[0].lower() == "family" and len(parts) >= 2:
            return parts[1].lower()
        if parts and parts[0].lower() in {"inet", "inet6", "ethernet-switching"}:
            return parts[0].lower()
    return None


def _vlan_context(context: list[str]) -> str | None:
    names = [item.split()[0].lower() for item in context]
    if "vlans" not in names:
        return None
    index = names.index("vlans")
    if len(context) <= index + 1:
        return None
    return context[index + 1]


def _firewall_context(
    context: list[str],
) -> tuple[
    Literal["ipv4", "ipv6"] | None,
    str | None,
    str | None,
]:
    family: Literal["ipv4", "ipv6"] | None = None
    filter_name: str | None = None
    term_name: str | None = None
    for item in context:
        parts = item.split()
        if len(parts) < 2:
            continue
        name = parts[0].lower()
        if name == "family":
            family = _junos_family(parts[1])
        elif name == "filter":
            filter_name = parts[1]
        elif name == "term":
            term_name = parts[1]
    return family, filter_name, term_name


def _prefix_list_context(context: list[str]) -> str | None:
    for item in context:
        parts = item.split()
        if len(parts) == 2 and parts[0].lower() == "prefix-list":
            return parts[1]
    return None


def _static_route_context(context: list[str]) -> str | None:
    for item in context:
        parts = item.split()
        if len(parts) == 2 and parts[0].lower() == "route":
            return parts[1]
    return None


def _bgp_context(context: list[str]) -> tuple[str | None, str | None]:
    group_name: str | None = None
    neighbor_address: str | None = None
    for item in context:
        parts = item.split()
        if len(parts) != 2:
            continue
        if parts[0].lower() == "group":
            group_name = parts[1]
        elif parts[0].lower() == "neighbor":
            neighbor_address = parts[1]
    return group_name, neighbor_address


def _ospf_context(context: list[str]) -> tuple[str | None, str | None]:
    area_id: str | None = None
    interface_name: str | None = None
    for item in context:
        parts = item.split()
        if len(parts) != 2:
            continue
        if parts[0].lower() == "area":
            area_id = parts[1]
        elif parts[0].lower() == "interface":
            interface_name = parts[1]
    return area_id, interface_name


def _normalize_ospf_area_id(value: str) -> str | None:
    try:
        if value.isdigit():
            numeric = int(value)
            if numeric > 0xFFFFFFFF:
                return None
            return str(ip_address(numeric))
        parsed = ip_address(value)
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None


def _parse_asn(value: str) -> int | None:
    if not value.isdigit():
        return None
    parsed = int(value)
    return parsed if 1 <= parsed <= 4_294_967_295 else None


def _parse_ip_address(value: str) -> str | None:
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _parse_router_id(value: str) -> str | None:
    parsed = _parse_ip_address(value)
    if parsed is None or ip_address(parsed).version != 4:
        return None
    return parsed


def _junos_acl_action(value: str) -> Literal["permit", "deny"] | None:
    lowered = value.lower()
    if lowered == "accept":
        return "permit"
    if lowered in {"discard", "reject"}:
        return "deny"
    return None


def _valid_vlan_id(value: int) -> bool:
    return 1 <= value <= 4094


def _parse_vlan_id(value: str) -> int | None:
    if not value.isdigit():
        return None
    vlan_id = int(value)
    return vlan_id if _valid_vlan_id(vlan_id) else None


def _junos_family(value: str) -> Literal["ipv4", "ipv6"] | None:
    lowered = value.lower()
    if lowered == "inet":
        return "ipv4"
    if lowered == "inet6":
        return "ipv6"
    return None


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _strip_comment(line: str) -> str:
    """Remove JunOS comments while keeping values such as IPv6 addresses intact."""

    if line.lstrip().startswith(("#", "/*", "*")):
        return ""
    return line.split("//", maxsplit=1)[0]
