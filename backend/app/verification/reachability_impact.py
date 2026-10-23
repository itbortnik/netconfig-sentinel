"""Bounded directional example-flow evidence; never severity or universal coverage."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.verification.batfish import BatfishExecution, BatfishResult

REACHABILITY_IMPACT_LIMITATIONS = (
    "Returned flows are examples, not all packets or the size of the affected flow space.",
    "Differential queries use ingress locations present and active in both snapshots.",
    "Source IP inference uses the after snapshot; removed ingress locations are not covered.",
    "Successful subnet delivery or exit does not establish delivery to an external device.",
    "No severity, whole-network safety, management access, approval or application is inferred.",
)
SUCCESS_DISPOSITIONS = frozenset({"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"})
ReachabilityDisposition = Literal[
    "ACCEPTED",
    "DELIVERED_TO_SUBNET",
    "EXITS_NETWORK",
    "DENIED_IN",
    "DENIED_OUT",
    "NO_ROUTE",
    "NULL_ROUTED",
    "NEIGHBOR_UNREACHABLE",
    "LOOP",
]
ImpactState = Literal["observed", "inconclusive", "not_observed", "unknown"]
ImpactReason = Literal[
    "query_completed",
    "empty_reachable_scope",
    "not_run",
    "unsupported_frame",
    "witness_limit_exceeded",
    "incomplete_traces",
    "ambiguous_witness",
    "unknown_disposition",
    "insufficient_information",
    "cleanup_unconfirmed",
]


class ReachabilityWitness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    flow_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_dispositions: tuple[ReachabilityDisposition, ...] = Field(min_length=1, max_length=16)
    after_dispositions: tuple[ReachabilityDisposition, ...] = Field(min_length=1, max_length=16)
    before_trace_count: int = Field(strict=True, ge=1, le=16)
    after_trace_count: int = Field(strict=True, ge=1, le=16)
    direction: Literal["loss", "gain"]

    @model_validator(mode="after")
    def complete_direction(self) -> Self:
        if (
            self.before_trace_count != len(self.before_dispositions)
            or self.after_trace_count != len(self.after_dispositions)
            or self.before_dispositions != tuple(sorted(self.before_dispositions))
            or self.after_dispositions != tuple(sorted(self.after_dispositions))
        ):
            raise ValueError("direction requires complete ordered trace dispositions")
        before = bool(SUCCESS_DISPOSITIONS.intersection(self.before_dispositions))
        after = bool(SUCCESS_DISPOSITIONS.intersection(self.after_dispositions))
        if before == after or self.direction != ("loss" if before else "gain"):
            raise ValueError("direction differs from the complete witness")
        return self


class ReachabilityImpact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["reachability-impact-0.1.0"] = "reachability-impact-0.1.0"
    state: ImpactState
    reason: ImpactReason
    direction: (
        Literal["loss_found", "gain_found", "loss_and_gain_found", "no_witnesses_returned"] | None
    )
    lost_witness_count: int | None = Field(strict=True, ge=0, le=64)
    gained_witness_count: int | None = Field(strict=True, ge=0, le=64)
    witnesses: tuple[ReachabilityWitness, ...] = Field(max_length=64)
    max_witnesses: Literal[64] = 64
    max_traces: Literal[16] = 16
    method: Literal["differential-success-example-flows-0.1.0"] = (
        "differential-success-example-flows-0.1.0"
    )
    limitations: tuple[str, ...] = REACHABILITY_IMPACT_LIMITATIONS

    @field_validator("max_witnesses", "max_traces", mode="before")
    @classmethod
    def strict_limits(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("directional bounds must be literal integers")
        return value

    @model_validator(mode="after")
    def consistent_observation(self) -> Self:
        if self.limitations != REACHABILITY_IMPACT_LIMITATIONS:
            raise ValueError("directional method limitations differ")
        observed = self.state == "observed"
        if self.state != "unknown":
            expected = {
                "observed": "query_completed",
                "inconclusive": "empty_reachable_scope",
                "not_observed": "not_run",
            }[self.state]
            if self.reason != expected:
                raise ValueError("reason differs from directional state")
        elif self.reason in {"query_completed", "empty_reachable_scope", "not_run"}:
            raise ValueError("unknown direction needs its actual interpretation failure")
        if not observed:
            if (
                self.direction is not None
                or self.lost_witness_count is not None
                or self.gained_witness_count is not None
                or self.witnesses
            ):
                raise ValueError("unobserved direction cannot claim witnesses or counts")
            return self
        hashes = tuple(row.flow_sha256 for row in self.witnesses)
        if len(set(hashes)) != len(hashes) or hashes != tuple(sorted(hashes)):
            raise ValueError("directional witness identities must be unique and ordered")
        losses = sum(row.direction == "loss" for row in self.witnesses)
        gains = len(self.witnesses) - losses
        direction = (
            "loss_and_gain_found"
            if losses and gains
            else "loss_found"
            if losses
            else "gain_found"
            if gains
            else "no_witnesses_returned"
        )
        if (self.direction, self.lost_witness_count, self.gained_witness_count) != (
            direction,
            losses,
            gains,
        ):
            raise ValueError("directional summary differs from its witnesses")
        return self


def empty_reachability_impact(state: ImpactState, reason: ImpactReason) -> ReachabilityImpact:
    return ReachabilityImpact(
        state=state,
        reason=reason,
        direction=None,
        lost_witness_count=None,
        gained_witness_count=None,
        witnesses=(),
    )


class BatfishDirectionalExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["batfish-execution-0.3.0"] = "batfish-execution-0.3.0"
    result: BatfishResult
    sdk_version: str | None = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$"
    )
    sdk_observation: Literal["observed", "not_observed", "metadata_unavailable"]
    reachability_impact: ReachabilityImpact

    @model_validator(mode="after")
    def bound_execution(self) -> Self:
        BatfishExecution(
            result=self.result,
            sdk_version=self.sdk_version,
            sdk_observation=self.sdk_observation,
        )
        result, impact = self.result, self.reachability_impact
        queried = result.status in {"inconclusive", "differences_found", "no_differences_in_scope"}
        if not queried:
            if (impact.state, impact.reason) != ("not_observed", "not_run"):
                raise ValueError("unperformed queries cannot claim directional interpretation")
        elif result.cleanup_complete is not True:
            if (impact.state, impact.reason) != ("unknown", "cleanup_unconfirmed"):
                raise ValueError("unconfirmed cleanup blocks directional observation")
        elif result.status == "inconclusive":
            if (impact.state, impact.reason) != ("inconclusive", "empty_reachable_scope"):
                raise ValueError("empty reachable scope cannot claim a directional observation")
        elif impact.state == "observed":
            if len(impact.witnesses) != result.difference_count:
                raise ValueError("directional witnesses differ from the differential result")
        elif impact.state != "unknown" or impact.reason == "cleanup_unconfirmed":
            raise ValueError("completed query requires observed or explicitly unknown direction")
        return self
