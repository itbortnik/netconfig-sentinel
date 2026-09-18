"""Typed contracts for declarative configuration policies."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain import Severity


class PolicyPlatform(StrEnum):
    """Parser platforms that a policy can evaluate."""

    CISCO_IOS = "cisco_ios"
    JUNIPER_JUNOS = "juniper_junos"


class ManagementField(StrEnum):
    """Management and observability facts exposed to declarative rules."""

    SSH_ENABLED = "management.ssh_enabled"
    SSH_VERSION = "management.ssh_version"
    TELNET_ENABLED = "management.telnet_enabled"
    AAA_ENABLED = "management.aaa_enabled"
    SNMP_VERSIONS = "management.snmp_versions"
    NTP_SERVERS = "management.ntp_servers"
    SYSLOG_SERVERS = "management.syslog_servers"


class AclField(StrEnum):
    """Derived ACL facts supported by deterministic evaluators."""

    EMPTY = "acl.empty"
    UNRESTRICTED_PERMIT = "acl.unrestricted_permit"
    TELNET_PERMITTED = "acl.telnet_permitted"
    MANAGEMENT_ACCESS_FROM_ANY = "acl.management_access_from_any"


class RoutingField(StrEnum):
    """Derived routing facts supported by deterministic evaluators."""

    BGP_ROUTER_ID_MISSING = "bgp.router_id_missing"
    BGP_NEIGHBOR_IS_LOCAL = "bgp.neighbor_is_local_address"
    OSPF_ROUTER_ID_MISSING = "ospf.router_id_missing"
    DEFAULT_ROUTE_DISCARDED = "routing.default_route_discarded"


class Layer2Field(StrEnum):
    """Derived interface and VLAN facts supported by deterministic evaluators."""

    ACCESS_VLAN_MISSING = "interface.access_vlan_missing"
    TRUNK_VLANS_UNRESTRICTED = "interface.trunk_vlans_unrestricted"
    SWITCHPORT_MODE_CONFLICT = "interface.switchport_mode_conflict"


class DeviceField(StrEnum):
    """Derived device identity facts supported by deterministic evaluators."""

    HOSTNAME_MISSING = "device.hostname_missing"


class PolicyOperator(StrEnum):
    """Small explicit operator set understood by the deterministic engine."""

    EQUALS = "equals"
    IS_EMPTY = "is_empty"
    CONTAINS_ANY = "contains_any"
    MATCHES = "matches"


_BOOLEAN_FIELDS = {
    ManagementField.SSH_ENABLED,
    ManagementField.TELNET_ENABLED,
    ManagementField.AAA_ENABLED,
}
_COLLECTION_FIELDS = {
    ManagementField.SNMP_VERSIONS,
    ManagementField.NTP_SERVERS,
    ManagementField.SYSLOG_SERVERS,
}
_STRING_FIELDS = {ManagementField.SSH_VERSION}


class PolicyRule(BaseModel):
    """One dependency-free declarative policy definition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^[a-z][a-z0-9_.]+$")
    title: str = Field(min_length=1)
    severity: Severity
    platforms: tuple[PolicyPlatform, ...] = Field(min_length=1)
    field: ManagementField | AclField | RoutingField | Layer2Field | DeviceField
    operator: PolicyOperator = PolicyOperator.EQUALS
    violation_value: bool | str | tuple[str, ...] | None = None
    expected_value: bool | str
    evidence_message: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    references: tuple[str, ...] = Field(min_length=1)

    @field_validator("platforms", "references")
    @classmethod
    def entries_must_be_unique(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("entries must be unique")
        return value

    @model_validator(mode="after")
    def condition_must_match_operator_and_field(self) -> PolicyRule:
        if self.operator is PolicyOperator.EQUALS:
            if self.field in _BOOLEAN_FIELDS:
                if not isinstance(self.violation_value, bool) or not isinstance(
                    self.expected_value, bool
                ):
                    raise ValueError("equals requires boolean values for this field")
            elif self.field in _STRING_FIELDS:
                if not isinstance(self.violation_value, str) or not isinstance(
                    self.expected_value, str
                ):
                    raise ValueError("equals requires string values for this field")
            else:
                raise ValueError("equals requires a scalar field")
        elif self.operator is PolicyOperator.IS_EMPTY:
            if self.field not in _COLLECTION_FIELDS or self.violation_value is not None:
                raise ValueError("is_empty requires a collection field and no value")
        elif self.operator is PolicyOperator.CONTAINS_ANY:
            if self.field not in _COLLECTION_FIELDS or not (
                isinstance(self.violation_value, tuple) and self.violation_value
            ):
                raise ValueError("contains_any requires a collection field and values")
        elif self.operator is PolicyOperator.MATCHES:
            if not isinstance(
                self.field, (AclField, RoutingField, Layer2Field, DeviceField)
            ) or (self.violation_value is not None):
                raise ValueError("matches requires a derived field and no value")
        return self
