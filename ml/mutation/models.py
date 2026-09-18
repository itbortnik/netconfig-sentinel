"""Strict contracts for reversible synthetic configuration mutations."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from app.domain import Vendor
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.datasets.deduplication import DatasetRecordReference

MUTATION_ENGINE_VERSION = "config-mutation-0.1.0"


class MutationType(StrEnum):
    """Minimum synthetic anomaly classes required by the dataset contract."""

    AAA_DISABLED = "aaa_disabled"
    TELNET_ENABLED = "telnet_enabled"
    SNMP_DOWNGRADE = "snmp_downgrade"
    PERMISSIVE_ACL = "permissive_acl"
    MISSING_ACL_ENTRY = "missing_acl_entry"
    VLAN_MISMATCH = "vlan_mismatch"
    INCORRECT_ACCESS_TRUNK_MODE = "incorrect_access_trunk_mode"
    BGP_REMOTE_AS_MISMATCH = "bgp_remote_as_mismatch"
    MISSING_BGP_NEIGHBOR = "missing_bgp_neighbor"
    OSPF_AREA_MISMATCH = "ospf_area_mismatch"
    REMOVED_STATIC_ROUTE = "removed_static_route"
    MANAGEMENT_EXPOSURE = "management_exposure"
    MISSING_NTP_SYSLOG = "missing_ntp_syslog"
    ROUTE_MAP_ORDER_CHANGE = "route_map_order_change"
    CONFLICTING_IP_ADDRESS = "conflicting_ip_address"


class MutationValidationStatus(StrEnum):
    """Outcome of one validation boundary."""

    PASSED = "passed"
    PARTIAL = "partial"
    NOT_RUN = "not_run"


class MutationOperation(BaseModel):
    """One exact line replacement and the data required to reverse it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mutation_type: MutationType
    precondition: str = Field(min_length=1, max_length=512)
    description: str = Field(min_length=1, max_length=512)
    expected_effect: str = Field(min_length=1, max_length=512)
    original_start_line: int = Field(ge=1)
    original_lines: tuple[str, ...]
    mutated_start_line: int = Field(ge=1)
    mutated_lines: tuple[str, ...]
    affected_lines: tuple[int, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def operation_must_change_text(self) -> MutationOperation:
        if not self.original_lines and not self.mutated_lines:
            raise ValueError("a mutation operation must contain a line change")
        if self.original_lines == self.mutated_lines:
            raise ValueError("a mutation operation must change its lines")
        if tuple(sorted(set(self.affected_lines))) != self.affected_lines:
            raise ValueError("affected lines must be sorted and unique")
        return self


class MutationSyntaxValidation(BaseModel):
    """Canonical-parser validation performed after mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: MutationValidationStatus
    parser: str = Field(min_length=1, max_length=64)
    parser_confidence: float = Field(ge=0.0, le=1.0)
    warning_count: int = Field(ge=0)
    unparsed_fragment_count: int = Field(ge=0)
    introduced_warning_count: int = Field(ge=0)
    introduced_unparsed_fragment_count: int = Field(ge=0)
    limitations: tuple[str, ...]


class MutationFormalValidation(BaseModel):
    """Status of optional external network-behavior validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: MutationValidationStatus
    validator: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=512)


class SyntheticAnomalyLabel(BaseModel):
    """A label that cannot be confused with a confirmed real anomaly."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mutation_type: MutationType
    category: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    synthetic: bool = True
    real_confirmed: bool = False

    @model_validator(mode="after")
    def label_must_remain_synthetic(self) -> SyntheticAnomalyLabel:
        if not self.synthetic or self.real_confirmed:
            raise ValueError("mutation labels must remain synthetic and unconfirmed")
        return self


class SyntheticMutationSample(BaseModel):
    """Reproducible mutated text, labels, validation, and reversible edits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine_version: str = Field(
        default=MUTATION_ENGINE_VERSION,
        pattern=r"^config-mutation-0\.1\.0$",
    )
    mutation_id: str = Field(pattern=r"^mutation-[0-9a-f]{24}$")
    source_record: DatasetRecordReference
    vendor: Vendor
    seed: int = Field(ge=0, le=2**63 - 1)
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutated_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutated_text: str = Field(min_length=1)
    operations: tuple[MutationOperation, ...] = Field(min_length=1, max_length=5)
    labels: tuple[SyntheticAnomalyLabel, ...] = Field(min_length=1, max_length=5)
    affected_lines: tuple[int, ...] = Field(min_length=1)
    syntax_validation: MutationSyntaxValidation
    formal_validation: MutationFormalValidation
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def sample_must_be_internally_consistent(self) -> SyntheticMutationSample:
        if self.original_sha256 == self.mutated_sha256:
            raise ValueError("a mutation must change the configuration hash")
        actual_hash = hashlib.sha256(self.mutated_text.encode("utf-8")).hexdigest()
        if actual_hash != self.mutated_sha256:
            raise ValueError("mutated text does not match its SHA-256")
        operation_types = tuple(operation.mutation_type for operation in self.operations)
        label_types = tuple(label.mutation_type for label in self.labels)
        if operation_types != label_types:
            raise ValueError("mutation operations and labels must have matching order")
        if len(operation_types) != len(set(operation_types)):
            raise ValueError("a sample cannot repeat a mutation type")
        if tuple(sorted(set(self.affected_lines))) != self.affected_lines:
            raise ValueError("sample affected lines must be sorted and unique")
        if self.syntax_validation.status is MutationValidationStatus.NOT_RUN:
            raise ValueError("persistable mutation samples require parser validation")
        return self
