"""Typed contracts for deterministic peer-group baselines."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain import CanonicalConfig, Vendor

type FeatureValue = bool | int | float | str | tuple[str, ...] | None


class PeerFeature(StrEnum):
    """Canonical facts eligible for exact peer consensus."""

    SSH_ENABLED = "management.ssh_enabled"
    SSH_VERSION = "management.ssh_version"
    TELNET_ENABLED = "management.telnet_enabled"
    AAA_ENABLED = "management.aaa_enabled"
    SNMP_VERSIONS = "management.snmp_versions"
    NTP_CONFIGURED = "management.ntp_configured"
    SYSLOG_CONFIGURED = "management.syslog_configured"
    VLAN_SET = "vlans.set"
    ACL_PATTERNS = "acls.patterns"
    BGP_PRESENT = "bgp.present"
    BGP_LOCAL_AS = "bgp.local_as"
    OSPF_PRESENT = "ospf.present"
    OSPF_AREAS = "ospf.areas"
    STATIC_ROUTE_DESTINATIONS = "static_routes.destinations"


class PeerGroupKey(BaseModel):
    """Identity fields that define a comparable group of devices."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: Vendor
    platform: str = Field(min_length=1)
    device_role: str = Field(min_length=1)
    site_class: str = Field(min_length=1)
    service_profile: str = Field(min_length=1)

    @classmethod
    def from_config(cls, config: CanonicalConfig) -> PeerGroupKey:
        values = {
            "device_role": config.device.role,
            "site_class": config.device.site_class,
            "service_profile": config.device.service_profile,
        }
        missing = [name for name, value in values.items() if value is None]
        if missing:
            raise ValueError(
                "peer-group metadata is missing: " + ", ".join(sorted(missing))
            )
        return cls(
            vendor=config.device.vendor,
            platform=config.device.platform,
            device_role=values["device_role"],
            site_class=values["site_class"],
            service_profile=values["service_profile"],
        )


class ConsensusFeature(BaseModel):
    """One peer feature whose exact value reached the configured consensus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: PeerFeature
    expected: FeatureValue
    support_count: int = Field(ge=1)
    sample_count: int = Field(ge=1)

    @model_validator(mode="after")
    def support_cannot_exceed_samples(self) -> ConsensusFeature:
        if self.support_count > self.sample_count:
            raise ValueError("support_count must not exceed sample_count")
        return self

    @property
    def support_ratio(self) -> float:
        return self.support_count / self.sample_count


class PeerBaseline(BaseModel):
    """Versioned consensus profile built from one explicit peer group."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_version: str = "peer-baseline-0.1.0"
    group: PeerGroupKey
    sample_count: int = Field(ge=2)
    consensus_threshold: float = Field(gt=0.5, le=1.0)
    features: tuple[ConsensusFeature, ...]
    unsupported_ratio_median: float = Field(ge=0.0, le=1.0)
    unsupported_ratio_limit: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_profile(self) -> PeerBaseline:
        fields = [feature.field for feature in self.features]
        if len(fields) != len(set(fields)):
            raise ValueError("baseline feature fields must be unique")
        if any(feature.sample_count != self.sample_count for feature in self.features):
            raise ValueError("feature sample counts must match the baseline")
        if any(
            feature.support_ratio < self.consensus_threshold
            for feature in self.features
        ):
            raise ValueError("every baseline feature must meet the consensus threshold")
        if self.unsupported_ratio_limit < self.unsupported_ratio_median:
            raise ValueError("unsupported ratio limit must not be below the median")
        return self
