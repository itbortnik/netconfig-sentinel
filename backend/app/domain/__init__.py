"""Domain contracts shared by API, parsers, and detectors."""

from app.domain.models import (
    CanonicalConfig,
    ConfigSource,
    DeviceInfo,
    Evidence,
    Finding,
    ManagementConfig,
    Severity,
    SourceLocation,
    UnparsedFragment,
    Vendor,
)

__all__ = [
    "CanonicalConfig",
    "ConfigSource",
    "DeviceInfo",
    "Evidence",
    "Finding",
    "ManagementConfig",
    "Severity",
    "SourceLocation",
    "UnparsedFragment",
    "Vendor",
]
