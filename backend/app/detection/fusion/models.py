"""Contracts for transparent multi-detector risk fusion."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RiskSource(StrEnum):
    """Signals understood by the first risk-fusion formula."""

    POLICY = "policy"
    PEER_GROUP = "peer_group"
    STATISTICAL = "statistical"
    TRANSFORMER = "transformer"
    VERIFICATION = "verification"


class SignalStatus(StrEnum):
    """Distinguish a completed zero result from an unavailable detector."""

    COMPLETED = "completed"
    UNAVAILABLE = "unavailable"


class VerificationImpact(StrEnum):
    """Supported formal verification outcomes for risk fusion."""

    NOT_RUN = "not_run"
    NO_ADVERSE_IMPACT = "no_adverse_impact"
    POLICY_REGRESSION = "policy_regression"
    LOSS_OF_REACHABILITY = "loss_of_reachability"


class RiskLevel(StrEnum):
    """Human-facing risk band derived from the fused numeric score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskComponent(BaseModel):
    """One auditable input contribution to a risk assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: RiskSource
    status: SignalStatus
    raw_score: float | None = Field(default=None, ge=0.0, le=1.0)
    configured_weight: float = Field(ge=0.0, le=1.0)
    effective_weight: float = Field(ge=0.0, le=1.0)
    finding_ids: tuple[UUID, ...] = ()

    @model_validator(mode="after")
    def status_must_match_score(self) -> RiskComponent:
        if self.status is SignalStatus.COMPLETED and self.raw_score is None:
            raise ValueError("completed components require a raw score")
        if self.status is SignalStatus.UNAVAILABLE and self.raw_score is not None:
            raise ValueError("unavailable components must not have a raw score")
        if self.status is SignalStatus.UNAVAILABLE and self.effective_weight != 0.0:
            raise ValueError("unavailable components must have zero effective weight")
        return self


class RiskAssessment(BaseModel):
    """Versioned result of transparent detector-score fusion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: UUID
    device_id: UUID
    score: float = Field(ge=0.0, le=1.0)
    level: RiskLevel
    components: tuple[RiskComponent, ...]
    guardrails: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    model_version: str = "risk-fusion-0.1.0"

    @model_validator(mode="after")
    def components_must_be_complete_and_unique(self) -> RiskAssessment:
        sources = [component.source for component in self.components]
        if len(sources) != len(set(sources)):
            raise ValueError("risk component sources must be unique")
        if set(sources) != set(RiskSource):
            raise ValueError("risk assessment must describe every supported source")
        effective_total = sum(component.effective_weight for component in self.components)
        if abs(effective_total - 1.0) > 1e-9:
            raise ValueError("effective component weights must sum to one")
        return self
