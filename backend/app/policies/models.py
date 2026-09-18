"""Typed contracts for declarative configuration policies."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain import Severity


class PolicyPlatform(StrEnum):
    """Parser platforms that a policy can evaluate."""

    CISCO_IOS = "cisco_ios"
    JUNIPER_JUNOS = "juniper_junos"


class ManagementField(StrEnum):
    """Management-plane boolean facts exposed to declarative rules."""

    SSH_ENABLED = "management.ssh_enabled"
    TELNET_ENABLED = "management.telnet_enabled"
    AAA_ENABLED = "management.aaa_enabled"


class PolicyRule(BaseModel):
    """One dependency-free, declarative boolean policy definition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^[a-z][a-z0-9_.]+$")
    title: str = Field(min_length=1)
    severity: Severity
    platforms: tuple[PolicyPlatform, ...] = Field(min_length=1)
    field: ManagementField
    violation_value: bool
    expected_value: bool
    evidence_message: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    references: tuple[str, ...] = Field(min_length=1)

    @field_validator("platforms", "references")
    @classmethod
    def entries_must_be_unique(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("entries must be unique")
        return value
