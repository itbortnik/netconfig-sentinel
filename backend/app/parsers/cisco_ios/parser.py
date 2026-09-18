"""Conservative line-oriented parser for the first Cisco IOS feature slice."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, ip_address, ip_interface, ip_network
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

_HOSTNAME = re.compile(r"^hostname\s+(?P<value>\S+)$", re.IGNORECASE)
_VERSION = re.compile(r"^version\s+(?P<value>\S+)", re.IGNORECASE)
_TRANSPORT_INPUT = re.compile(r"^transport\s+input\s+(?P<value>.+)$", re.IGNORECASE)
_NTP_SERVER = re.compile(r"^ntp\s+server\s+(?P<value>\S+)", re.IGNORECASE)
_SYSLOG_SERVER = re.compile(r"^logging\s+host\s+(?P<value>\S+)", re.IGNORECASE)
_INTERFACE = re.compile(r"^interface\s+(?P<value>\S+)$", re.IGNORECASE)
_VLAN = re.compile(r"^vlan\s+(?P<value>\d+)$", re.IGNORECASE)
_BGP = re.compile(r"^router\s+bgp\s+(?P<value>\S+)$", re.IGNORECASE)
_ACL = re.compile(
    r"^(?P<family>ip|ipv6)\s+access-list\s+"
    r"(?:(?P<kind>standard|extended)\s+)?(?P<name>\S+)$",
    re.IGNORECASE,
)
_IPV4_ADDRESS = re.compile(
    r"^ip\s+address\s+(?P<address>\S+)\s+(?P<mask>\S+)(?:\s+secondary)?$",
    re.IGNORECASE,
)
_IPV6_ADDRESS = re.compile(
    r"^ipv6\s+address\s+(?P<address>\S+)(?:\s+eui-64)?$", re.IGNORECASE
)


@dataclass
class _CiscoInterface:
    name: str
    description: str | None = None
    enabled: bool | None = None
    addresses: list[InterfaceAddress] = field(default_factory=list)
    switchport_mode: Literal["access", "trunk"] | None = None
    access_vlan: VlanReference | None = None
    native_vlan: VlanReference | None = None
    allowed_vlans: VlanSet | None = None
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self) -> InterfaceConfig:
        return InterfaceConfig(
            name=self.name,
            description=self.description,
            enabled=self.enabled,
            addresses=self.addresses,
            switchport_mode=self.switchport_mode,
            access_vlan=self.access_vlan,
            native_vlan=self.native_vlan,
            allowed_vlans=self.allowed_vlans,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _CiscoVlan:
    vlan_id: int
    name: str | None = None
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
class _CiscoAcl:
    name: str
    family: Literal["ipv4", "ipv6"]
    kind: Literal["standard", "extended"]
    rules: list[AclRule] = field(default_factory=list)
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self) -> AclConfig:
        return AclConfig(
            name=self.name,
            family=self.family,
            kind=self.kind,
            rules=self.rules,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _CiscoPrefixList:
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
class _CiscoBgpNeighbor:
    address: str
    remote_as: int | None = None
    description: str | None = None
    update_source: str | None = None
    enabled: bool | None = None
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    source_lines: list[tuple[int, str]] = field(default_factory=list)

    def build(self, local_as: int) -> BgpNeighborConfig | None:
        if self.remote_as is None:
            return None
        family: Literal["ipv4", "ipv6"] = (
            "ipv4" if ip_address(self.address).version == 4 else "ipv6"
        )
        return BgpNeighborConfig(
            address=self.address,
            family=family,
            remote_as=self.remote_as,
            description=self.description,
            session_type="internal" if self.remote_as == local_as else "external",
            update_source=self.update_source,
            enabled=self.enabled,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


@dataclass
class _CiscoBgp:
    local_as: int
    router_id: str | None = None
    neighbors: dict[str, _CiscoBgpNeighbor] = field(default_factory=dict)
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def ensure_neighbor(
        self, address: str, number: int, raw_line: str
    ) -> _CiscoBgpNeighbor:
        if address not in self.neighbors:
            neighbor = _CiscoBgpNeighbor(address=address)
            neighbor.facts["address"].append((number, raw_line))
            self.neighbors[address] = neighbor
        return self.neighbors[address]

    def build(
        self,
        warnings: list[str],
        unparsed: list[UnparsedFragment],
    ) -> BgpConfig:
        neighbors: list[BgpNeighborConfig] = []
        known_unparsed_lines = {
            fragment.location.source_lines[0] for fragment in unparsed
        }
        for neighbor in self.neighbors.values():
            built = neighbor.build(self.local_as)
            if built is not None:
                neighbors.append(built)
                continue
            warnings.append(f"BGP neighbor {neighbor.address} has no valid remote AS")
            for number, raw_line in neighbor.source_lines:
                if number not in known_unparsed_lines:
                    unparsed.append(
                        UnparsedFragment(
                            raw_text=raw_line,
                            location=source_location(
                                [(number, raw_line)], parser_confidence=0.0
                            ),
                        )
                    )
                    known_unparsed_lines.add(number)
        return BgpConfig(
            local_as=self.local_as,
            router_id=self.router_id,
            neighbors=neighbors,
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


class CiscoIOSParser(VendorParser):
    """Parse identity and management features without pretending full IOS coverage."""

    vendor = Vendor.CISCO
    platform = "ios"

    def parse(
        self,
        text: str,
        *,
        filename: str,
        collected_at: datetime | None = None,
    ) -> CanonicalConfig:
        hostname: str | None = None
        os_version: str | None = None
        aaa_enabled = False
        ssh_enabled = False
        telnet_enabled = False
        snmp_versions: set[str] = set()
        ntp_servers: list[str] = []
        syslog_servers: list[str] = []
        interfaces: list[_CiscoInterface] = []
        current_interface: _CiscoInterface | None = None
        vlans: dict[int, _CiscoVlan] = {}
        current_vlan: _CiscoVlan | None = None
        acls: list[_CiscoAcl] = []
        current_acl: _CiscoAcl | None = None
        prefix_lists: dict[tuple[str, str], _CiscoPrefixList] = {}
        static_routes: list[StaticRouteConfig] = []
        bgp: _CiscoBgp | None = None
        current_bgp: _CiscoBgp | None = None
        facts: dict[str, list[tuple[int, str]]] = defaultdict(list)
        unparsed: list[UnparsedFragment] = []
        warnings: list[str] = []
        significant_count = 0

        for number, raw_line in enumerate(text.splitlines(), start=1):
            command = raw_line.strip()
            if not command:
                continue
            if command.startswith("!"):
                current_interface = None
                current_vlan = None
                current_acl = None
                current_bgp = None
                continue
            significant_count += 1
            lowered = command.lower()

            if match := _INTERFACE.fullmatch(command):
                current_interface = _CiscoInterface(name=match.group("value"))
                current_vlan = None
                current_acl = None
                current_bgp = None
                current_interface.facts["name"].append((number, raw_line))
                interfaces.append(current_interface)
                continue

            if match := _VLAN.fullmatch(command):
                vlan_id = int(match.group("value"))
                current_interface = None
                current_acl = None
                current_bgp = None
                if not _valid_vlan_id(vlan_id):
                    warnings.append(f"invalid VLAN identifier at line {number}")
                    unparsed.append(
                        UnparsedFragment(
                            raw_text=raw_line,
                            location=source_location(
                                [(number, raw_line)], parser_confidence=0.0
                            ),
                        )
                    )
                    current_vlan = None
                    continue
                if vlan_id not in vlans:
                    current_vlan = _CiscoVlan(vlan_id=vlan_id)
                    current_vlan.facts["vlan_id"].append((number, raw_line))
                    vlans[vlan_id] = current_vlan
                else:
                    current_vlan = vlans[vlan_id]
                continue

            if match := _ACL.fullmatch(command):
                family: Literal["ipv4", "ipv6"] = (
                    "ipv4" if match.group("family").lower() == "ip" else "ipv6"
                )
                raw_kind = match.group("kind")
                kind: Literal["standard", "extended"] = (
                    "standard"
                    if raw_kind is not None and raw_kind.lower() == "standard"
                    else "extended"
                )
                current_interface = None
                current_vlan = None
                current_acl = _CiscoAcl(
                    name=match.group("name"), family=family, kind=kind
                )
                current_acl.facts["name"].append((number, raw_line))
                acls.append(current_acl)
                continue

            if match := _BGP.fullmatch(command):
                local_as = _parse_asn(match.group("value"))
                current_interface = None
                current_vlan = None
                current_acl = None
                if local_as is None:
                    warnings.append(f"invalid BGP local AS at line {number}")
                    unparsed.append(
                        UnparsedFragment(
                            raw_text=raw_line,
                            location=source_location(
                                [(number, raw_line)], parser_confidence=0.0
                            ),
                        )
                    )
                    current_bgp = None
                    continue
                if bgp is not None and bgp.local_as != local_as:
                    warnings.append(f"multiple BGP processes at line {number}")
                    unparsed.append(
                        UnparsedFragment(
                            raw_text=raw_line,
                            location=source_location(
                                [(number, raw_line)], parser_confidence=0.0
                            ),
                        )
                    )
                    current_bgp = None
                    continue
                if bgp is None:
                    bgp = _CiscoBgp(local_as=local_as)
                    bgp.facts["local_as"].append((number, raw_line))
                current_bgp = bgp
                continue

            if current_interface is not None and raw_line[:1].isspace():
                if lowered == "exit":
                    current_interface = None
                    continue
                if _consume_interface_command(
                    current_interface, command, number, raw_line, warnings
                ):
                    continue
                unparsed.append(
                    UnparsedFragment(
                        raw_text=raw_line,
                        location=source_location([(number, raw_line)], parser_confidence=0.0),
                    )
                )
                continue

            if current_vlan is not None and raw_line[:1].isspace():
                if lowered == "exit":
                    current_vlan = None
                    continue
                if lowered.startswith("name "):
                    current_vlan.name = command.split(maxsplit=1)[1]
                    current_vlan.facts["name"].append((number, raw_line))
                    continue
                unparsed.append(
                    UnparsedFragment(
                        raw_text=raw_line,
                        location=source_location([(number, raw_line)], parser_confidence=0.0),
                    )
                )
                continue

            if current_acl is not None and raw_line[:1].isspace():
                if lowered == "exit":
                    current_acl = None
                    continue
                rule = _parse_acl_rule(current_acl, command, number, raw_line)
                if rule is not None:
                    current_acl.rules.append(rule)
                    continue
                warnings.append(f"unsupported ACL entry at line {number}")
                unparsed.append(
                    UnparsedFragment(
                        raw_text=raw_line,
                        location=source_location([(number, raw_line)], parser_confidence=0.0),
                    )
                )
                continue

            if current_bgp is not None and raw_line[:1].isspace():
                if lowered == "exit":
                    current_bgp = None
                    continue
                if lowered == "exit-address-family":
                    continue
                if _consume_bgp_command(
                    current_bgp, command, number, raw_line, warnings
                ):
                    continue
                unparsed.append(
                    UnparsedFragment(
                        raw_text=raw_line,
                        location=source_location(
                            [(number, raw_line)], parser_confidence=0.0
                        ),
                    )
                )
                continue

            current_interface = None
            current_vlan = None
            current_acl = None
            current_bgp = None
            if lowered in {"end", "exit", "configure terminal"} or lowered.startswith(
                "line vty "
            ):
                continue

            if match := _HOSTNAME.fullmatch(command):
                hostname = match.group("value")
                facts["hostname"].append((number, raw_line))
            elif match := _VERSION.match(command):
                os_version = match.group("value")
                facts["os_version"].append((number, raw_line))
            elif lowered == "aaa new-model":
                aaa_enabled = True
                facts["aaa_enabled"].append((number, raw_line))
            elif lowered == "no aaa new-model":
                aaa_enabled = False
                facts["aaa_enabled"].append((number, raw_line))
            elif lowered.startswith("ip ssh "):
                ssh_enabled = True
                facts["ssh_enabled"].append((number, raw_line))
            elif match := _TRANSPORT_INPUT.fullmatch(command):
                protocols = set(match.group("value").lower().split())
                ssh_enabled = ssh_enabled or "ssh" in protocols
                telnet_enabled = telnet_enabled or "telnet" in protocols or "all" in protocols
                if "ssh" in protocols:
                    facts["ssh_enabled"].append((number, raw_line))
                if "telnet" in protocols or "all" in protocols:
                    facts["telnet_enabled"].append((number, raw_line))
            elif lowered.startswith("snmp-server group ") and " v3 " in f" {lowered} ":
                snmp_versions.add("v3")
                facts["snmp_versions"].append((number, raw_line))
            elif lowered.startswith("snmp-server community "):
                snmp_versions.update({"v1", "v2c"})
                facts["snmp_versions"].append((number, raw_line))
            elif match := _NTP_SERVER.match(command):
                ntp_servers.append(match.group("value"))
                facts["ntp_servers"].append((number, raw_line))
            elif match := _SYSLOG_SERVER.match(command):
                syslog_servers.append(match.group("value"))
                facts["syslog_servers"].append((number, raw_line))
            elif lowered.startswith(("ip prefix-list ", "ipv6 prefix-list ")):
                if not _consume_prefix_list(
                    prefix_lists, command, number, raw_line, warnings
                ):
                    unparsed.append(
                        UnparsedFragment(
                            raw_text=raw_line,
                            location=source_location(
                                [(number, raw_line)], parser_confidence=0.0
                            ),
                        )
                    )
            elif lowered.startswith(("ip route ", "ipv6 route ")):
                route = _parse_static_route(command, number, raw_line, warnings)
                if route is not None:
                    static_routes.append(route)
                else:
                    unparsed.append(
                        UnparsedFragment(
                            raw_text=raw_line,
                            location=source_location(
                                [(number, raw_line)], parser_confidence=0.0
                            ),
                        )
                    )
            else:
                unparsed.append(
                    UnparsedFragment(
                        raw_text=raw_line,
                        location=source_location([(number, raw_line)], parser_confidence=0.0),
                    )
                )

        if hostname is None:
            warnings.append("hostname was not found")

        bgp_config = bgp.build(warnings, unparsed) if bgp is not None else None
        confidence = _overall_confidence(significant_count, len(unparsed))
        device_provenance = {
            key: source_location(value)
            for key, value in facts.items()
            if key in {"hostname", "os_version"}
        }
        management_provenance = {
            key: source_location(value)
            for key, value in facts.items()
            if key not in {"hostname", "os_version"}
        }
        return CanonicalConfig(
            source=config_source(text, filename, collected_at),
            device=DeviceInfo(
                hostname=hostname,
                vendor=self.vendor,
                platform=self.platform,
                os_version=os_version,
                provenance=device_provenance,
            ),
            management=ManagementConfig(
                ssh_enabled=ssh_enabled,
                telnet_enabled=telnet_enabled,
                aaa_enabled=aaa_enabled,
                snmp_versions=[
                    version for version in ("v1", "v2c", "v3") if version in snmp_versions
                ],
                ntp_servers=list(dict.fromkeys(ntp_servers)),
                syslog_servers=list(dict.fromkeys(syslog_servers)),
                provenance=management_provenance,
            ),
            interfaces=[interface.build() for interface in interfaces],
            vlans=[vlan.build() for vlan in vlans.values()],
            acls=[acl.build() for acl in acls],
            prefix_lists=[prefix_list.build() for prefix_list in prefix_lists.values()],
            static_routes=static_routes,
            bgp=bgp_config,
            unparsed_fragments=unparsed,
            parse_warnings=warnings,
            parser_confidence=confidence,
        )


def _parse_acl_rule(
    acl: _CiscoAcl, command: str, number: int, raw_line: str
) -> AclRule | None:
    tokens = command.split()
    if not tokens:
        return None
    sequence: int | None = None
    if tokens[0].isdigit():
        sequence = int(tokens.pop(0))
    if not tokens or tokens[0].lower() not in {"permit", "deny"}:
        return None
    action: Literal["permit", "deny"] = (
        "permit" if tokens.pop(0).lower() == "permit" else "deny"
    )
    location = source_location([(number, raw_line)])
    provenance = {"rule": location}

    if acl.kind == "standard":
        parsed = _parse_acl_address(tokens, 0, acl.family)
        if parsed is None:
            return None
        source_addresses, index = parsed
        return AclRule(
            sequence=sequence,
            action=action,
            source_addresses=source_addresses,
            options=tokens[index:],
            provenance=provenance,
        )

    if not tokens:
        return None
    protocol = tokens[0].lower()
    parsed_source = _parse_acl_address(tokens, 1, acl.family)
    if parsed_source is None:
        return None
    source_addresses, index = parsed_source
    source_ports, index = _parse_acl_ports(tokens, index)
    parsed_destination = _parse_acl_address(tokens, index, acl.family)
    if parsed_destination is None:
        return None
    destination_addresses, index = parsed_destination
    destination_ports, index = _parse_acl_ports(tokens, index)
    return AclRule(
        sequence=sequence,
        action=action,
        protocol=protocol,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        source_ports=source_ports,
        destination_ports=destination_ports,
        options=tokens[index:],
        provenance=provenance,
    )


def _parse_acl_address(
    tokens: list[str], index: int, family: Literal["ipv4", "ipv6"]
) -> tuple[list[str], int] | None:
    if index >= len(tokens):
        return None
    token = tokens[index]
    lowered = token.lower()
    if lowered == "any":
        return ["any"], index + 1
    if lowered == "host" and index + 1 < len(tokens):
        suffix = 32 if family == "ipv4" else 128
        try:
            network = ip_network(f"{tokens[index + 1]}/{suffix}", strict=False)
        except ValueError:
            return None
        if network.version != (4 if family == "ipv4" else 6):
            return None
        return [str(network)], index + 2
    if "/" in token:
        try:
            network = ip_network(token, strict=False)
        except ValueError:
            return None
        if network.version != (4 if family == "ipv4" else 6):
            return None
        return [str(network)], index + 1
    if family == "ipv4" and index + 1 < len(tokens):
        try:
            wildcard = IPv4Address(tokens[index + 1])
            netmask = IPv4Address((~int(wildcard)) & 0xFFFFFFFF)
            network = ip_network(f"{token}/{netmask}", strict=False)
        except ValueError:
            return None
        return [str(network)], index + 2
    return None


def _parse_acl_ports(tokens: list[str], index: int) -> tuple[list[str], int]:
    if index >= len(tokens):
        return [], index
    operator = tokens[index].lower()
    operand_counts = {"eq": 1, "neq": 1, "lt": 1, "gt": 1, "range": 2}
    count = operand_counts.get(operator)
    if count is None or index + count >= len(tokens):
        return [], index
    operands = tokens[index + 1 : index + count + 1]
    return [f"{operator}:{'-'.join(operands)}"], index + count + 1


def _consume_prefix_list(
    prefix_lists: dict[tuple[str, str], _CiscoPrefixList],
    command: str,
    number: int,
    raw_line: str,
    warnings: list[str],
) -> bool:
    tokens = command.split()
    if len(tokens) < 5 or tokens[1].lower() != "prefix-list":
        return False
    family: Literal["ipv4", "ipv6"] = (
        "ipv4" if tokens[0].lower() == "ip" else "ipv6"
    )
    name = tokens[2]
    index = 3
    sequence: int | None = None
    if index < len(tokens) and tokens[index].lower() == "seq":
        if index + 1 >= len(tokens) or not tokens[index + 1].isdigit():
            warnings.append(f"invalid prefix-list sequence at line {number}")
            return False
        sequence = int(tokens[index + 1])
        index += 2
    if index + 1 >= len(tokens) or tokens[index].lower() not in {"permit", "deny"}:
        return False
    action: Literal["permit", "deny"] = (
        "permit" if tokens[index].lower() == "permit" else "deny"
    )
    prefix = tokens[index + 1]
    index += 2
    ge: int | None = None
    le: int | None = None
    while index < len(tokens):
        key = tokens[index].lower()
        if key not in {"ge", "le"} or index + 1 >= len(tokens):
            return False
        if not tokens[index + 1].isdigit():
            return False
        if key == "ge":
            ge = int(tokens[index + 1])
        else:
            le = int(tokens[index + 1])
        index += 2
    try:
        network = ip_network(prefix, strict=False)
        rule = PrefixListRule(
            sequence=sequence,
            action=action,
            prefix=str(network),
            ge=ge,
            le=le,
            provenance=source_location([(number, raw_line)]),
        )
    except ValueError:
        warnings.append(f"invalid prefix-list entry at line {number}")
        return False
    if network.version != (4 if family == "ipv4" else 6):
        warnings.append(f"prefix-list address family mismatch at line {number}")
        return False
    list_key = (family, name)
    if list_key not in prefix_lists:
        prefix_list = _CiscoPrefixList(name=name, family=family)
        prefix_list.facts["name"].append((number, raw_line))
        prefix_lists[list_key] = prefix_list
    prefix_lists[list_key].rules.append(rule)
    return True


def _consume_bgp_command(
    bgp: _CiscoBgp,
    command: str,
    number: int,
    raw_line: str,
    warnings: list[str],
) -> bool:
    tokens = command.split()
    lowered = [token.lower() for token in tokens]
    if lowered[:2] == ["bgp", "router-id"] and len(tokens) == 3:
        try:
            router_id = ip_address(tokens[2])
        except ValueError:
            warnings.append(f"invalid BGP router ID at line {number}")
            return False
        if router_id.version != 4:
            warnings.append(f"invalid BGP router ID at line {number}")
            return False
        bgp.router_id = str(router_id)
        bgp.facts["router_id"].append((number, raw_line))
        return True

    enabled: bool | None = None
    if lowered[:1] == ["no"]:
        if len(tokens) != 4 or lowered[1] != "neighbor" or lowered[3] != "shutdown":
            return False
        address_token = tokens[2]
        enabled = True
    else:
        if len(tokens) < 3 or lowered[0] != "neighbor":
            return False
        address_token = tokens[1]

    try:
        address = str(ip_address(address_token))
    except ValueError:
        warnings.append(f"invalid BGP neighbor address at line {number}")
        return False
    neighbor = bgp.ensure_neighbor(address, number, raw_line)
    neighbor.source_lines.append((number, raw_line))
    if enabled is True:
        neighbor.enabled = True
        neighbor.facts["enabled"].append((number, raw_line))
        return True

    attribute = lowered[2]
    if attribute == "remote-as" and len(tokens) == 4:
        remote_as = _parse_asn(tokens[3])
        if remote_as is None:
            warnings.append(f"invalid BGP remote AS at line {number}")
            return False
        neighbor.remote_as = remote_as
        neighbor.facts["remote_as"].append((number, raw_line))
        return True
    if attribute == "description" and len(tokens) >= 4:
        neighbor.description = " ".join(tokens[3:])
        neighbor.facts["description"].append((number, raw_line))
        return True
    if attribute == "update-source" and len(tokens) == 4:
        neighbor.update_source = tokens[3]
        neighbor.facts["update_source"].append((number, raw_line))
        return True
    if attribute == "shutdown" and len(tokens) == 3:
        neighbor.enabled = False
        neighbor.facts["enabled"].append((number, raw_line))
        return True
    return False


def _parse_asn(value: str) -> int | None:
    if not value.isdigit():
        return None
    parsed = int(value)
    return parsed if 1 <= parsed <= 4_294_967_295 else None


def _parse_static_route(
    command: str,
    number: int,
    raw_line: str,
    warnings: list[str],
) -> StaticRouteConfig | None:
    tokens = command.split()
    family: Literal["ipv4", "ipv6"]
    destination_value: str
    index: int
    if tokens[:2] == ["ip", "route"]:
        family = "ipv4"
        if len(tokens) < 5 or tokens[2].lower() == "vrf":
            return None
        destination_value = f"{tokens[2]}/{tokens[3]}"
        index = 4
    elif tokens[:2] == ["ipv6", "route"]:
        family = "ipv6"
        if len(tokens) < 4 or tokens[2].lower() == "vrf":
            return None
        destination_value = tokens[2]
        index = 3
    else:
        return None

    try:
        destination = ip_network(destination_value, strict=False)
    except ValueError:
        warnings.append(f"invalid static route at line {number}")
        return None
    expected_version = 4 if family == "ipv4" else 6
    if destination.version != expected_version or index >= len(tokens):
        warnings.append(f"invalid static route at line {number}")
        return None

    next_hop: str | None = None
    outgoing_interface: str | None = None
    discard = False
    target = tokens[index]
    index += 1
    if target.lower() == "null0":
        outgoing_interface = target
        discard = True
    else:
        parsed_target = _parse_route_next_hop(target, family)
        if parsed_target is not None:
            next_hop = parsed_target
        elif target[:1].isdigit():
            warnings.append(f"invalid static route next hop at line {number}")
            return None
        else:
            outgoing_interface = target
            if index < len(tokens):
                parsed_target = _parse_route_next_hop(tokens[index], family)
                if parsed_target is not None:
                    next_hop = parsed_target
                    index += 1

    preference: int | None = None
    if index < len(tokens) and tokens[index].isdigit():
        preference = int(tokens[index])
        index += 1
    if index != len(tokens):
        return None

    location = source_location([(number, raw_line)])
    provenance = {"destination": location}
    if next_hop is not None:
        provenance["next_hop"] = location
    if outgoing_interface is not None:
        provenance["outgoing_interface"] = location
    if preference is not None:
        provenance["preference"] = location
    if discard:
        provenance["discard"] = location
    try:
        return StaticRouteConfig(
            family=family,
            destination=str(destination),
            next_hop=next_hop,
            outgoing_interface=outgoing_interface,
            preference=preference,
            discard=discard,
            provenance=provenance,
        )
    except ValueError:
        warnings.append(f"invalid static route at line {number}")
        return None


def _parse_route_next_hop(
    value: str, family: Literal["ipv4", "ipv6"]
) -> str | None:
    try:
        parsed = ip_address(value)
    except ValueError:
        return None
    if parsed.version != (4 if family == "ipv4" else 6):
        return None
    return str(parsed)


def _consume_interface_command(
    interface: _CiscoInterface,
    command: str,
    number: int,
    raw_line: str,
    warnings: list[str],
) -> bool:
    lowered = command.lower()
    if lowered.startswith("description "):
        interface.description = command.split(maxsplit=1)[1]
        interface.facts["description"].append((number, raw_line))
        return True
    if lowered == "shutdown":
        interface.enabled = False
        interface.facts["enabled"].append((number, raw_line))
        return True
    if lowered == "no shutdown":
        interface.enabled = True
        interface.facts["enabled"].append((number, raw_line))
        return True
    if lowered == "no ip address":
        return True
    if lowered in {"switchport mode access", "switchport mode trunk"}:
        interface.switchport_mode = "access" if lowered.endswith("access") else "trunk"
        interface.facts["switchport_mode"].append((number, raw_line))
        return True
    if lowered.startswith("switchport access vlan "):
        vlan_id = _parse_single_vlan_id(command.rsplit(maxsplit=1)[1])
        if vlan_id is None:
            warnings.append(f"invalid access VLAN at line {number}")
            return False
        interface.access_vlan = VlanReference(
            vlan_id=vlan_id,
            provenance=source_location([(number, raw_line)]),
        )
        return True
    if lowered.startswith("switchport trunk native vlan "):
        vlan_id = _parse_single_vlan_id(command.rsplit(maxsplit=1)[1])
        if vlan_id is None:
            warnings.append(f"invalid native VLAN at line {number}")
            return False
        interface.native_vlan = VlanReference(
            vlan_id=vlan_id,
            provenance=source_location([(number, raw_line)]),
        )
        return True
    allowed_prefix = "switchport trunk allowed vlan "
    if lowered.startswith(allowed_prefix):
        selection = command[len(allowed_prefix) :]
        parsed_selection = _parse_vlan_selection(selection, number, raw_line)
        if parsed_selection is None:
            warnings.append(f"unsupported allowed VLAN selection at line {number}")
            return False
        interface.allowed_vlans = parsed_selection
        return True
    if match := _IPV4_ADDRESS.fullmatch(command):
        value = f"{match.group('address')}/{match.group('mask')}"
        return _add_interface_address(
            interface, value, "ipv4", number, raw_line, warnings
        )
    if match := _IPV6_ADDRESS.fullmatch(command):
        return _add_interface_address(
            interface, match.group("address"), "ipv6", number, raw_line, warnings
        )
    return False


def _add_interface_address(
    interface: _CiscoInterface,
    value: str,
    family: Literal["ipv4", "ipv6"],
    number: int,
    raw_line: str,
    warnings: list[str],
) -> bool:
    try:
        parsed = ip_interface(value)
    except ValueError:
        warnings.append(f"invalid {family} interface address at line {number}")
        return False
    expected_version = 4 if family == "ipv4" else 6
    if parsed.version != expected_version:
        warnings.append(f"invalid {family} interface address at line {number}")
        return False
    interface.addresses.append(
        InterfaceAddress(
            address=str(parsed),
            family=family,
            provenance=source_location([(number, raw_line)]),
        )
    )
    return True


def _valid_vlan_id(value: int) -> bool:
    return 1 <= value <= 4094


def _parse_single_vlan_id(value: str) -> int | None:
    if not value.isdigit():
        return None
    vlan_id = int(value)
    return vlan_id if _valid_vlan_id(vlan_id) else None


def _parse_vlan_selection(
    value: str, number: int, raw_line: str
) -> VlanSet | None:
    lowered = value.lower().strip()
    provenance = source_location([(number, raw_line)])
    if lowered == "all":
        return VlanSet(all_vlans=True, provenance=provenance)
    if lowered == "none":
        return VlanSet(provenance=provenance)
    if lowered.startswith(("add ", "remove ", "except ")):
        return None

    vlan_ids: set[int] = set()
    for item in lowered.split(","):
        part = item.strip()
        if not part:
            return None
        if "-" in part:
            bounds = part.split("-", maxsplit=1)
            if len(bounds) != 2 or not all(bound.isdigit() for bound in bounds):
                return None
            start, end = (int(bound) for bound in bounds)
            if not _valid_vlan_id(start) or not _valid_vlan_id(end) or start > end:
                return None
            vlan_ids.update(range(start, end + 1))
        else:
            vlan_id = _parse_single_vlan_id(part)
            if vlan_id is None:
                return None
            vlan_ids.add(vlan_id)
    return VlanSet(vlan_ids=sorted(vlan_ids), provenance=provenance)


def _overall_confidence(significant_count: int, unparsed_count: int) -> float:
    if significant_count == 0:
        return 0.0
    unsupported_ratio = unparsed_count / significant_count
    return round(max(0.20, 1.0 - (0.60 * unsupported_ratio)), 4)
