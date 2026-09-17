"""Canonical, vendor-neutral domain models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class StrictModel(BaseModel):
    """Base for externally visible contracts with no silent extra fields."""

    model_config = ConfigDict(extra="forbid")


class Vendor(StrEnum):
    """Vendors supported by the canonical model in this iteration."""

    CISCO = "cisco"
    JUNIPER = "juniper"


class Severity(StrEnum):
    """Potential impact assigned by a detector or policy."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceLocation(StrictModel):
    """Trace a normalized fact back to immutable source text."""

    source_lines: list[int] = Field(min_length=1)
    raw_text_hash: str = Field(pattern=SHA256_PATTERN)
    parser_confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("source_lines")
    @classmethod
    def validate_source_lines(cls, value: list[int]) -> list[int]:
        if any(line < 1 for line in value):
            raise ValueError("source line numbers must be positive")
        if value != sorted(set(value)):
            raise ValueError("source line numbers must be sorted and unique")
        return value


class ConfigSource(StrictModel):
    """Identity and collection metadata for an uploaded configuration."""

    filename: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=SHA256_PATTERN)
    collected_at: datetime

    @field_validator("filename")
    @classmethod
    def filename_must_be_a_leaf(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value:
            raise ValueError("filename must not contain a path")
        return value


class DeviceInfo(StrictModel):
    """Vendor-neutral device identity."""

    hostname: str | None = None
    vendor: Vendor
    platform: str
    os_version: str | None = None
    role: str | None = None
    site: str | None = None
    provenance: dict[str, SourceLocation] = Field(default_factory=dict)


class ManagementConfig(StrictModel):
    """Normalized management-plane features supported by the MVP parser."""

    ssh_enabled: bool = False
    telnet_enabled: bool = False
    aaa_enabled: bool = False
    snmp_versions: list[Literal["v1", "v2c", "v3"]] = Field(default_factory=list)
    ntp_servers: list[str] = Field(default_factory=list)
    syslog_servers: list[str] = Field(default_factory=list)
    provenance: dict[str, SourceLocation] = Field(default_factory=dict)


class UnparsedFragment(StrictModel):
    """A non-empty command that this parser version did not interpret."""

    raw_text: str
    location: SourceLocation


class CanonicalConfig(StrictModel):
    """Stable vendor-neutral representation produced by every parser."""

    schema_version: Literal["1.0"] = "1.0"
    source: ConfigSource
    device: DeviceInfo
    management: ManagementConfig = Field(default_factory=ManagementConfig)
    interfaces: list[dict[str, Any]] = Field(default_factory=list)
    vlans: list[dict[str, Any]] = Field(default_factory=list)
    acls: list[dict[str, Any]] = Field(default_factory=list)
    prefix_lists: list[dict[str, Any]] = Field(default_factory=list)
    static_routes: list[dict[str, Any]] = Field(default_factory=list)
    bgp: dict[str, Any] | None = None
    ospf: list[dict[str, Any]] = Field(default_factory=list)
    unparsed_fragments: list[UnparsedFragment] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    parser_confidence: float = Field(ge=0.0, le=1.0)


class Evidence(StrictModel):
    """One independently inspectable reason for a finding."""

    kind: str
    message: str
    source_location: SourceLocation | None = None


class Finding(StrictModel):
    """Unified result contract for current and future detectors."""

    finding_id: UUID
    device_id: UUID
    detector: str
    category: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    affected_lines: list[int] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    observed: dict[str, Any] = Field(default_factory=dict)
    expected: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    model_version: str

    @field_validator("affected_lines")
    @classmethod
    def validate_affected_lines(cls, value: list[int]) -> list[int]:
        if any(line < 1 for line in value):
            raise ValueError("affected line numbers must be positive")
        if value != sorted(set(value)):
            raise ValueError("affected line numbers must be sorted and unique")
        return value
