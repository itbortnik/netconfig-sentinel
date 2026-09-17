"""Small explicit parser registry used by the API and ingestion layer."""

from __future__ import annotations

from datetime import datetime

from app.domain import CanonicalConfig
from app.parsers.base import VendorParser
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.detection import detect_vendor
from app.parsers.juniper_junos import JuniperJunosParser

_PARSERS: dict[str, VendorParser] = {
    "cisco_ios": CiscoIOSParser(),
    "juniper_junos": JuniperJunosParser(),
}


def registered_parsers() -> set[str]:
    """Return a copy so callers cannot mutate the registry."""

    return set(_PARSERS)


def get_parser(parser_key: str) -> VendorParser:
    """Resolve a registered vendor adapter by stable key."""

    try:
        return _PARSERS[parser_key]
    except KeyError as error:
        raise ValueError(f"unsupported parser: {parser_key}") from error


def parse_configuration(
    text: str,
    *,
    filename: str,
    collected_at: datetime | None = None,
) -> CanonicalConfig:
    """Detect the vendor and return the canonical representation."""

    detection = detect_vendor(text)
    parser = get_parser(detection.parser_key)
    return parser.parse(text, filename=filename, collected_at=collected_at)
