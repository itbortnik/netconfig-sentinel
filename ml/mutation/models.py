"""Strict contracts for reversible synthetic configuration mutations."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Literal

from app.domain import RouteMapClauseConfig, RouteMapConfig, Vendor
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from ml.datasets.deduplication import DatasetRecordReference

MUTATION_ENGINE_VERSION = "config-mutation-0.1.0"
STRUCTURAL_MUTATION_ENGINE_VERSION = "config-mutation-0.2.0"
ROUTE_MAP_MUTATION_ENGINE_VERSION = "config-mutation-0.3.0"


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


class MutationLineChange(BaseModel):
    """One textual diff hunk; a deletion has no affected line in the result."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["insert", "delete", "replace"]
    original_start_line: int = Field(strict=True, ge=1, le=50_001)
    original_line_count: int = Field(strict=True, ge=0, le=50_000)
    mutated_start_line: int = Field(strict=True, ge=1, le=50_001)
    mutated_line_count: int = Field(strict=True, ge=0, le=50_000)

    @model_validator(mode="after")
    def exact_kind(self) -> MutationLineChange:
        before, after = self.original_line_count, self.mutated_line_count
        expected = "replace" if before and after else "delete" if before else "insert"
        if not (before or after) or self.kind != expected:
            raise ValueError("diff kind differs from its source/result spans")
        return self


class MutationLocalization(BaseModel):
    """Versioned final-parent-to-result textual alignment, not causal ML truth."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["mutation-localization-0.1.0"] = "mutation-localization-0.1.0"
    original_line_count: int = Field(strict=True, ge=1, le=50_000)
    mutated_line_count: int = Field(strict=True, ge=1, le=50_000)
    changes: tuple[MutationLineChange, ...] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def ordered_bounded_spans(self) -> MutationLocalization:
        original_end = mutated_end = 1
        for change in self.changes:
            if (
                change.original_start_line < original_end
                or change.mutated_start_line < mutated_end
                or change.original_start_line - original_end
                != change.mutated_start_line - mutated_end
                or change.original_start_line + change.original_line_count
                > self.original_line_count + 1
                or change.mutated_start_line + change.mutated_line_count
                > self.mutated_line_count + 1
            ):
                raise ValueError("diff spans must be ordered, disjoint and within their source")
            original_end = change.original_start_line + change.original_line_count
            mutated_end = change.mutated_start_line + change.mutated_line_count
        if self.original_line_count + 1 - original_end != (
            self.mutated_line_count + 1 - mutated_end
        ):
            raise ValueError("unchanged diff tails must have matching lengths")
        return self

    @property
    def changed_result_lines(self) -> tuple[int, ...]:
        return tuple(
            line
            for change in self.changes
            for line in range(
                change.mutated_start_line,
                change.mutated_start_line + change.mutated_line_count,
            )
        )


def route_map_clause_body(clause: RouteMapClauseConfig) -> str:
    return json.dumps(
        clause.model_dump(exclude={"sequence", "provenance", "normalization_complete"}),
        sort_keys=True,
        separators=(",", ":"),
    )


class RouteMapOrderEvidence(BaseModel):
    """Configured two-clause body swap, bound to exact source/result inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["route-map-order-validation-0.1.0"] = "route-map-order-validation-0.1.0"
    canonical_schema_version: Literal["1.2"] = "1.2"
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutated_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before: RouteMapConfig
    after: RouteMapConfig
    vendor_syntax_checked: Literal[False] = False
    network_behavior_checked: Literal[False] = False

    @field_validator("before", "after", mode="before")
    @classmethod
    def revalidate_clause_facts(cls, value: Any) -> Any:
        return value.model_dump(warnings=False) if isinstance(value, RouteMapConfig) else value

    @model_validator(mode="after")
    def exact_configured_order_change(self) -> RouteMapOrderEvidence:
        if self.original_sha256 == self.mutated_sha256 or (
            self.before.name != self.after.name
            or not self.before.normalization_complete
            or not self.after.normalization_complete
            or [item.sequence for item in self.before.clauses]
            != [item.sequence for item in self.after.clauses]
        ):
            raise ValueError("route-map order source or complete clause binding differs")
        previous = [route_map_clause_body(item) for item in self.before.clauses]
        current = [route_map_clause_body(item) for item in self.after.clauses]
        if sorted(previous) != sorted(current) or sum(
            left != right for left, right in zip(previous, current, strict=True)
        ) != 2:
            raise ValueError("route-map order validation requires a two-clause body permutation")
        return self


class SyntheticMutationSample(BaseModel):
    """Reproducible mutated text, labels, validation, and reversible edits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine_version: str = Field(
        default=MUTATION_ENGINE_VERSION,
        pattern=r"^config-mutation-0\.[123]\.0$",
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
    affected_lines: tuple[int, ...]
    localization: MutationLocalization | None = None
    route_map_validation: RouteMapOrderEvidence | None = None
    syntax_validation: MutationSyntaxValidation
    formal_validation: MutationFormalValidation
    limitations: tuple[str, ...]

    @model_validator(mode="before")
    @classmethod
    def structural_seed_type(cls, value: Any) -> Any:
        if (
            isinstance(value, dict)
            and value.get("engine_version")
            in {STRUCTURAL_MUTATION_ENGINE_VERSION, ROUTE_MAP_MUTATION_ENGINE_VERSION}
            and type(value.get("seed")) is not int
        ):
            raise ValueError("structural mutation seed must be an integer")
        return value

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
        if self.engine_version in {
            STRUCTURAL_MUTATION_ENGINE_VERSION,
            ROUTE_MAP_MUTATION_ENGINE_VERSION,
        }:
            expected_vendor = (
                Vendor.JUNIPER
                if self.engine_version == STRUCTURAL_MUTATION_ENGINE_VERSION
                else Vendor.CISCO
            )
            if self.vendor is not expected_vendor or self.localization is None:
                raise ValueError(
                    "versioned structural samples require vendor and final localization"
                )
            if (
                self.localization.mutated_line_count != len(self.mutated_text.splitlines())
                or self.affected_lines != self.localization.changed_result_lines
                or len(self.mutated_text.encode("utf-8")) > 1_048_576
            ):
                raise ValueError("structural localization differs from the result")
        elif self.localization is not None or not self.affected_lines:
            raise ValueError("released samples retain their original nonempty line contract")
        if self.engine_version != ROUTE_MAP_MUTATION_ENGINE_VERSION:
            if self.route_map_validation is not None:
                raise ValueError("route-map order evidence requires engine 0.3")
        elif MutationType.ROUTE_MAP_ORDER_CHANGE in operation_types:
            if self.route_map_validation is None or (
                self.route_map_validation.original_sha256 != self.original_sha256
                or self.route_map_validation.mutated_sha256 != self.mutated_sha256
            ):
                raise ValueError("route-map evidence differs from the generated inputs")
        elif self.route_map_validation is not None:
            raise ValueError("route-map evidence requires the matching mutation operation")
        if self.engine_version == ROUTE_MAP_MUTATION_ENGINE_VERSION and (
            self.formal_validation.status is not MutationValidationStatus.NOT_RUN
        ):
            raise ValueError("route-map parser evidence cannot promote network formal status")
        if self.syntax_validation.status is MutationValidationStatus.NOT_RUN:
            raise ValueError("persistable mutation samples require parser validation")
        return self

    @model_serializer(mode="wrap")
    def preserve_released_serialization(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.engine_version == MUTATION_ENGINE_VERSION:
            result.pop("localization", None)
        if self.engine_version != ROUTE_MAP_MUTATION_ENGINE_VERSION:
            result.pop("route_map_validation", None)
        return result
