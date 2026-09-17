"""Conservative JunOS parser for set-style and hierarchical management config."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime

from app.domain import (
    CanonicalConfig,
    DeviceInfo,
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
        self.unparsed: list[UnparsedFragment] = []
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
        tokens = command.split()
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
        else:
            return False
        return True

    def consume_block(
        self, context: list[str], block: str, number: int, raw_line: str
    ) -> bool:
        name = block.split()[0].lower()
        context_names = [item.split()[0].lower() for item in context]
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

    def consume_leaf(
        self, context: list[str], leaf: str, number: int, raw_line: str
    ) -> bool:
        context_names = [item.split()[0].lower() for item in context]
        tokens = leaf.split()
        if not tokens:
            return True
        lowered = [token.lower() for token in tokens]

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

    def build(
        self, *, text: str, filename: str, collected_at: datetime | None
    ) -> CanonicalConfig:
        warnings = [] if self.hostname is not None else ["hostname was not found"]
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
            unparsed_fragments=self.unparsed,
            parse_warnings=warnings,
            parser_confidence=_overall_confidence(
                self.significant_count, len(self.unparsed)
            ),
        )


def _strip_comment(line: str) -> str:
    """Remove JunOS comments while keeping values such as IPv6 addresses intact."""

    if line.lstrip().startswith(("#", "/*", "*")):
        return ""
    return line.split("//", maxsplit=1)[0]
