"""Content-based vendor detection with inspectable evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VendorDetection:
    """Vendor adapter key plus evidence and a bounded confidence score."""

    parser_key: str
    confidence: float
    matched_markers: tuple[str, ...]


class UnsupportedVendorError(ValueError):
    """Raised when content does not identify a supported vendor safely."""


_CISCO_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("hostname", re.compile(r"(?m)^\s*hostname\s+\S+\s*$", re.IGNORECASE)),
    ("ios_version", re.compile(r"(?m)^\s*version\s+\d", re.IGNORECASE)),
    ("line_vty", re.compile(r"(?m)^\s*line\s+vty\b", re.IGNORECASE)),
    ("ios_interface", re.compile(r"(?m)^\s*interface\s+\S+", re.IGNORECASE)),
    ("ios_router", re.compile(r"(?m)^\s*router\s+(?:bgp|ospf)\b", re.IGNORECASE)),
    (
        "ios_management",
        re.compile(r"(?m)^\s*(?:ip ssh|aaa new-model|snmp-server)\b", re.IGNORECASE),
    ),
)

_JUNIPER_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("set_system", re.compile(r"(?m)^\s*set\s+system\s+", re.IGNORECASE)),
    ("junos_header", re.compile(r"(?m)^\s*##\s+Last commit:", re.IGNORECASE)),
    ("system_block", re.compile(r"(?m)^\s*system\s*\{", re.IGNORECASE)),
    ("host_name", re.compile(r"(?m)^\s*host-name\s+\S+\s*;", re.IGNORECASE)),
    ("junos_interfaces", re.compile(r"(?m)^\s*interfaces\s*\{", re.IGNORECASE)),
    ("junos_protocols", re.compile(r"(?m)^\s*protocols\s*\{", re.IGNORECASE)),
)


def _matches(
    text: str, markers: tuple[tuple[str, re.Pattern[str]], ...]
) -> tuple[str, ...]:
    return tuple(name for name, pattern in markers if pattern.search(text))


def detect_vendor(text: str) -> VendorDetection:
    """Select a parser only when vendor-specific markers provide clear evidence."""

    cisco = _matches(text, _CISCO_MARKERS)
    juniper = _matches(text, _JUNIPER_MARKERS)

    if not cisco and not juniper:
        raise UnsupportedVendorError("configuration does not contain supported vendor markers")
    if len(cisco) == len(juniper):
        raise UnsupportedVendorError("configuration vendor is ambiguous")

    if len(cisco) > len(juniper):
        confidence = min(0.99, 0.60 + (0.08 * len(cisco)) - (0.05 * len(juniper)))
        return VendorDetection("cisco_ios", confidence, cisco)

    confidence = min(0.99, 0.60 + (0.08 * len(juniper)) - (0.05 * len(cisco)))
    return VendorDetection("juniper_junos", confidence, juniper)
