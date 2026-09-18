"""Canonical, vendor-neutral domain models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import ip_interface
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class InterfaceAddress(StrictModel):
    """Canonical host address with prefix length and exact source provenance."""

    address: str
    family: Literal["ipv4", "ipv6"]
    provenance: SourceLocation

    @field_validator("address")
    @classmethod
    def canonicalize_address(cls, value: str) -> str:
        try:
            return str(ip_interface(value))
        except ValueError as error:
            raise ValueError("address must be a valid IPv4 or IPv6 interface") from error

    @model_validator(mode="after")
    def family_must_match_address(self) -> InterfaceAddress:
        parsed = ip_interface(self.address)
        expected_family = "ipv4" if parsed.version == 4 else "ipv6"
        if self.family != expected_family:
            raise ValueError(f"family must be {expected_family} for {self.address}")
        return self


class VlanReference(StrictModel):
    """A VLAN referenced by numeric identifier, vendor name, or both."""

    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    name: str | None = Field(default=None, min_length=1)
    provenance: SourceLocation

    @model_validator(mode="after")
    def require_identifier_or_name(self) -> VlanReference:
        if self.vlan_id is None and self.name is None:
            raise ValueError("a VLAN reference needs vlan_id, name, or both")
        return self


class VlanSet(StrictModel):
    """Normalized explicit/all VLAN selection used by trunk-like interfaces."""

    vlan_ids: list[int] = Field(default_factory=list)
    vlan_names: list[str] = Field(default_factory=list)
    all_vlans: bool = False
    provenance: SourceLocation

    @field_validator("vlan_ids")
    @classmethod
    def validate_vlan_ids(cls, value: list[int]) -> list[int]:
        if any(vlan_id < 1 or vlan_id > 4094 for vlan_id in value):
            raise ValueError("VLAN identifiers must be between 1 and 4094")
        if value != sorted(set(value)):
            raise ValueError("VLAN identifiers must be sorted and unique")
        return value

    @field_validator("vlan_names")
    @classmethod
    def validate_vlan_names(cls, value: list[str]) -> list[str]:
        if any(not name for name in value):
            raise ValueError("VLAN names must not be empty")
        if value != list(dict.fromkeys(value)):
            raise ValueError("VLAN names must be unique")
        return value


class InterfaceConfig(StrictModel):
    """Vendor-neutral physical interface or JunOS logical unit."""

    name: str = Field(min_length=1)
    unit: str | None = None
    description: str | None = None
    enabled: bool | None = None
    addresses: list[InterfaceAddress] = Field(default_factory=list)
    switchport_mode: Literal["access", "trunk"] | None = None
    access_vlan: VlanReference | None = None
    native_vlan: VlanReference | None = None
    allowed_vlans: VlanSet | None = None
    provenance: dict[str, SourceLocation] = Field(default_factory=dict)


class VlanConfig(StrictModel):
    """Canonical VLAN definition."""

    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    name: str | None = Field(default=None, min_length=1)
    provenance: dict[str, SourceLocation] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_identifier_or_name(self) -> VlanConfig:
        if self.vlan_id is None and self.name is None:
            raise ValueError("a VLAN definition needs vlan_id, name, or both")
        return self


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
    interfaces: list[InterfaceConfig] = Field(default_factory=list)
    vlans: list[VlanConfig] = Field(default_factory=list)
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
