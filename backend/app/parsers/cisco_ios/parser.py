"""Conservative line-oriented parser for the first Cisco IOS feature slice."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_interface
from typing import Literal

from app.domain import (
    CanonicalConfig,
    DeviceInfo,
    InterfaceAddress,
    InterfaceConfig,
    ManagementConfig,
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
                continue
            significant_count += 1
            lowered = command.lower()

            if match := _INTERFACE.fullmatch(command):
                current_interface = _CiscoInterface(name=match.group("value"))
                current_vlan = None
                current_interface.facts["name"].append((number, raw_line))
                interfaces.append(current_interface)
                continue

            if match := _VLAN.fullmatch(command):
                vlan_id = int(match.group("value"))
                current_interface = None
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

            current_interface = None
            current_vlan = None
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
            else:
                unparsed.append(
                    UnparsedFragment(
                        raw_text=raw_line,
                        location=source_location([(number, raw_line)], parser_confidence=0.0),
                    )
                )

        if hostname is None:
            warnings.append("hostname was not found")

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
            unparsed_fragments=unparsed,
            parse_warnings=warnings,
            parser_confidence=confidence,
        )


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
