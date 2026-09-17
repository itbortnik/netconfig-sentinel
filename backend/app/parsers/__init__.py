"""Vendor detection and parsing entry points."""

from app.parsers.detection import VendorDetection, detect_vendor
from app.parsers.registry import get_parser, parse_configuration, registered_parsers

__all__ = [
    "VendorDetection",
    "detect_vendor",
    "get_parser",
    "parse_configuration",
    "registered_parsers",
]
