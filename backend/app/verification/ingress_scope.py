"""Bounded selected ingress/source-IP observations, separate from formal verification."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.verification.batfish import BatfishResult, ReachabilityScope
from app.verification.ingress_scope_worker import (
    INGRESS_LIMITATIONS,
    INGRESS_METHOD,
    MAX_OBSERVATION_BYTES,
    derived_fields,
    empty_scope,
    json_bytes,
    validate_assignment,
    validate_interface,
)
from app.verification.reachability_impact import BatfishDirectionalExecution, ReachabilityImpact

AcquisitionState = Literal["observed", "unknown", "not_observed"]
AcquisitionReason = Literal[
    "query_completed",
    "not_run",
    "query_failed",
    "unsupported_answer",
    "unsupported_location",
    "incomplete_assignment",
    "budget_exceeded",
    "cleanup_unconfirmed",
]


class IngressInterfaceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")
    node: str = Field(strict=True, pattern=r"^[A-Za-z0-9_-]{1,128}$")
    interface: str = Field(strict=True, min_length=1, max_length=128)
    canonical_id_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    location_rendering: str = Field(strict=True, min_length=1, max_length=512)
    active: bool = Field(strict=True)
    switchport: bool = Field(strict=True)
    interface_type: str = Field(strict=True, pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    concrete_ipv4_prefixes: tuple[str, ...] = Field(max_length=64)
    eligible: bool | None = Field(strict=True)
    eligibility_reason: Literal[
        "active_concrete_ipv4", "inactive", "switchport", "no_concrete_ipv4"
    ]
    source_ip_rendering: str = Field(strict=True, min_length=1, max_length=4096)
    source_ip_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_observation(self) -> Self:
        validate_interface(self.model_dump(mode="json"))
        return self


class IngressSourceAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")
    canonical_id_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_ip_rendering: str = Field(strict=True, min_length=1, max_length=4096)
    source_ip_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_assignment(self) -> Self:
        validate_assignment(self.model_dump(mode="json"))
        return self


class IngressSideObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")
    interfaces: tuple[IngressInterfaceObservation, ...] = Field(max_length=256)


class IngressScopeObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")
    version: Literal["ingress-scope-0.1.0"] = "ingress-scope-0.1.0"
    before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: ReachabilityScope
    network_name: str | None = Field(default=None, pattern=r"^sentinel-[0-9a-f]{32}$")
    acquisition_state: AcquisitionState
    reason: AcquisitionReason
    before: IngressSideObservation | None
    after: IngressSideObservation | None
    eligibility_complete: bool | None = Field(strict=True)
    selected_before_only: tuple[str, ...] | None = Field(max_length=256)
    selected_after_only: tuple[str, ...] | None = Field(max_length=256)
    common_eligible: tuple[str, ...] | None = Field(max_length=256)
    before_eligible_only: tuple[str, ...] | None = Field(max_length=256)
    after_eligible_only: tuple[str, ...] | None = Field(max_length=256)
    after_common_assignments: tuple[IngressSourceAssignment, ...] | None = Field(max_length=256)
    semantic_ip_sets_verified: Literal[False] = False
    complete_flow_coverage: Literal[False] = False
    source_assignment_context: Literal["after"] = "after"
    method: Literal["selected-interface-concrete-ipv4-origination-0.1.0"] = INGRESS_METHOD
    limitations: tuple[str, ...] = INGRESS_LIMITATIONS

    @field_validator("semantic_ip_sets_verified", "complete_flow_coverage", mode="before")
    @classmethod
    def strict_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("scope observations cannot establish semantic sets or flow coverage")
        return value

    @model_validator(mode="after")
    def complete_capture_and_derived_sets(self) -> Self:
        data = self.model_dump(mode="json")
        if self.limitations != INGRESS_LIMITATIONS:
            raise ValueError("ingress method limitations differ")
        if len(json_bytes(data)) > MAX_OBSERVATION_BYTES:
            raise ValueError("ingress observation exceeds byte budget")
        if self.acquisition_state == "observed":
            if self.reason != "query_completed" or self.before is None or self.after is None:
                raise ValueError("observed acquisition requires both complete sides")
            if self.network_name is None:
                raise ValueError("observed acquisition requires network binding")
            for side in (self.before, self.after):
                if any(row.node != self.scope.start_node for row in side.interfaces):
                    raise ValueError("interface identity differs from requested node")
            expected = derived_fields(data["before"], data["after"])
            if any(data[key] != value for key, value in expected.items()):
                raise ValueError("ingress derived sets differ from complete observations")
        else:
            expected_reason = "not_run" if self.acquisition_state == "not_observed" else None
            if expected_reason is not None and self.reason != expected_reason:
                raise ValueError("unperformed acquisition requires not_run")
            if self.acquisition_state == "unknown" and self.reason in {
                "query_completed",
                "not_run",
            }:
                raise ValueError("unknown acquisition requires its failure reason")
            fields = (
                "before",
                "after",
                "eligibility_complete",
                "selected_before_only",
                "selected_after_only",
                "common_eligible",
                "before_eligible_only",
                "after_eligible_only",
                "after_common_assignments",
            )
            if any(data[key] is not None for key in fields):
                raise ValueError("unobserved acquisition cannot claim sides or derived sets")
        return self


def empty_ingress_scope(
    before_sha256: str,
    after_sha256: str,
    scope: ReachabilityScope,
    network_name: str | None = None,
    *,
    state: AcquisitionState = "not_observed",
    reason: AcquisitionReason = "not_run",
) -> IngressScopeObservation:
    return IngressScopeObservation.model_validate(
        empty_scope(
            dict(
                before_sha256=before_sha256,
                after_sha256=after_sha256,
                scope=scope.model_dump(mode="json"),
                network_name=network_name,
            ),
            state,
            reason,
        )
    )


class BatfishScopeExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")
    version: Literal["batfish-execution-0.4.0"] = "batfish-execution-0.4.0"
    result: BatfishResult
    sdk_version: str | None = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$"
    )
    sdk_observation: Literal["observed", "not_observed", "metadata_unavailable"]
    reachability_impact: ReachabilityImpact
    ingress_scope: IngressScopeObservation

    @model_validator(mode="after")
    def bound_execution(self) -> Self:
        BatfishDirectionalExecution(
            result=self.result,
            sdk_version=self.sdk_version,
            sdk_observation=self.sdk_observation,
            reachability_impact=self.reachability_impact,
        )
        result, observation = self.result, self.ingress_scope
        if (
            observation.before_sha256,
            observation.after_sha256,
            observation.scope,
            observation.network_name,
        ) != (result.before_sha256, result.after_sha256, result.scope, result.network_name):
            raise ValueError("ingress observation differs from execution bindings")
        queried = result.status in {"inconclusive", "differences_found", "no_differences_in_scope"}
        if not queried:
            if (observation.acquisition_state, observation.reason) != ("not_observed", "not_run"):
                raise ValueError("unperformed reachability cannot claim ingress acquisition")
        elif result.cleanup_complete is not True:
            if (observation.acquisition_state, observation.reason) != (
                "unknown",
                "cleanup_unconfirmed",
            ):
                raise ValueError("unconfirmed cleanup blocks ingress acquisition")
        elif (
            observation.acquisition_state == "not_observed"
            or observation.reason == "cleanup_unconfirmed"
        ):
            raise ValueError("completed reachability requires actual acquisition outcome")
        return self
