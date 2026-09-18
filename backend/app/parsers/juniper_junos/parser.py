"""Conservative JunOS parser for set-style and hierarchical management config."""

from __future__ import annotations

import re
import shlex
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
    facts: dict[str, list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def build(self, base: _JunosInterface | None = None) -> InterfaceConfig:
        description = self.description
        enabled = self.enabled
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
        return InterfaceConfig(
            name=self.name,
            unit=self.unit,
            description=description,
            enabled=enabled,
            addresses=self.addresses,
            provenance={key: source_location(value) for key, value in facts.items()},
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
        else:
            return False
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
        return False

    def consume_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        name = block.split()[0].lower()
        context_names = [item.split()[0].lower() for item in context]
        if name == "interfaces" and not context:
            return True
        if "interfaces" in context_names:
            return self.consume_interface_block(context, block, number, raw_line)
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
            return _junos_family(parts[1]) is not None
        if name in {"inet", "inet6"} and interface_name is not None:
            return True
        if name == "address" and interface_name is not None and len(parts) >= 2:
            family = _family_from_context(context)
            if family is None:
                return False
            interface = self.ensure_interface(interface_name, unit, number, raw_line)
            return self.add_interface_address(
                interface, parts[1], family, number, raw_line
            )
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

    def consume_interface_leaf(
        self, context: list[str], leaf: str, number: int, raw_line: str
    ) -> bool:
        interface_name, unit, family = _interface_context(context)
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
        names_with_units = {
            name for name, unit in self.interfaces if unit is not None
        }
        for (name, unit), interface in self.interfaces.items():
            base = self.interfaces.get((name, None))
            if unit is None and name in names_with_units and not interface.addresses:
                continue
            result.append(interface.build(base if unit is not None else None))
        return result

    def build(
        self, *, text: str, filename: str, collected_at: datetime | None
    ) -> CanonicalConfig:
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
