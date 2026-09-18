"""Domain contracts shared by API, parsers, and detectors."""

from app.domain.models import (
    CanonicalConfig,
    ConfigSource,
    DeviceInfo,
    Evidence,
    Finding,
    InterfaceAddress,
    InterfaceConfig,
    ManagementConfig,
    Severity,
    SourceLocation,
    UnparsedFragment,
    Vendor,
    VlanConfig,
    VlanReference,
    VlanSet,
)

__all__ = [
    "CanonicalConfig",
    "ConfigSource",
    "DeviceInfo",
    "Evidence",
    "Finding",
    "InterfaceAddress",
    "InterfaceConfig",
    "ManagementConfig",
    "Severity",
    "SourceLocation",
    "UnparsedFragment",
    "Vendor",
    "VlanConfig",
    "VlanReference",
    "VlanSet",
]
