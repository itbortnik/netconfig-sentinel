"""Append-only configuration-model attempts, not a new analysis or verification."""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, StrictBool, field_validator, model_validator

from app.api.contracts import SnapshotBinding
from ml.evaluation.contracts import Digest, Frozen
from ml.evaluation.metrics import canonical_hash
from ml.inference.config_contracts import ConfigurationInferenceReport

MAX_CONFIGURATION_MODEL_BYTES = 4 * 1024 * 1024


def fingerprint(value: BaseModel) -> str:
    return canonical_hash(value.model_dump(mode="json"))


class RunConfigurationModel(Frozen):
    inference_id: UUID
    analysis_id: UUID
    source_sha256: Digest
    model_sha256: Digest
    allow_local_model_context: StrictBool = False


class ConfigurationModelCapabilities(Frozen):
    version: Literal["configuration-model-capabilities-0.1.0"] = (
        "configuration-model-capabilities-0.1.0"
    )
    inference: Literal["configured", "disabled"]
    model_sha256: Digest | None = None
    health_checked: Literal[False] = False

    @field_validator("health_checked", mode="before")
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("configuration is not a health check")
        return value

    @model_validator(mode="after")
    def selected(self) -> Self:
        if (self.inference == "configured") != (self.model_sha256 is not None):
            raise ValueError("configured inference requires an operator pin")
        return self


class ConfigurationModelIntent(Frozen):
    version: Literal["configuration-model-intent-0.1.0"] = "configuration-model-intent-0.1.0"
    request: RunConfigurationModel
    source: SnapshotBinding
    analysis_sha256: Digest
    total_lines: int = Field(ge=1, le=10000, strict=True)
    created_at: datetime

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if (
            self.request.allow_local_model_context is not True
            or self.source.source_sha256 != self.request.source_sha256
            or self.created_at.utcoffset() is None
            or self.created_at < self.source.created_at
        ):
            raise ValueError("configuration model intent binding differs")
        return self


class ConfigurationModelOutcome(Frozen):
    version: Literal["configuration-model-outcome-0.1.0"] = "configuration-model-outcome-0.1.0"
    inference_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    status: Literal["completed", "failed"]
    report: ConfigurationInferenceReport | None = None

    @model_validator(mode="after")
    def accepted(self) -> Self:
        if self.completed_at.utcoffset() is None or (
            (self.status == "completed") != (self.report is not None)
        ):
            raise ValueError("configuration model outcome differs")
        return self


class ConfigurationModelRun(Frozen):
    version: Literal["configuration-model-run-0.1.0"] = "configuration-model-run-0.1.0"
    inference_id: UUID
    analysis_id: UUID
    source: SnapshotBinding
    analysis_sha256: Digest
    model_sha256: Digest
    total_lines: int = Field(ge=1, le=10000, strict=True)
    created_at: datetime
    completed_at: datetime | None
    status: Literal["pending", "completed", "failed"]
    intent_sha256: Digest
    outcome_sha256: Digest | None
    report: ConfigurationInferenceReport | None
    attempt_limit: Literal[1] = 1
    risk_fused: Literal[False] = False
    requires_human_review: Literal[True] = True

    @field_validator("attempt_limit", mode="before")
    @classmethod
    def exact_attempt(cls, value: object) -> int:
        if type(value) is not int or value != 1:
            raise ValueError("one reserved attempt, not measured execution count")
        return value

    @field_validator("risk_fused", "requires_human_review", mode="before")
    @classmethod
    def exact_flags(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("exact boolean flags required")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if (
            self.created_at.utcoffset() is None
            or self.created_at < self.source.created_at
            or (self.status == "pending") != (self.completed_at is None)
            or (self.status == "pending") != (self.outcome_sha256 is None)
            or (self.status == "completed") != (self.report is not None)
        ):
            raise ValueError("configuration model projection differs")
        if self.completed_at is not None and (
            self.completed_at.utcoffset() is None or self.completed_at < self.created_at
        ):
            raise ValueError("configuration model timestamps differ")
        if self.report is not None and (
            self.report.model.model_sha256 != self.model_sha256
            or self.report.prediction.raw_source_sha256 != self.source.source_sha256
            or self.report.prediction.total_lines != self.total_lines
        ):
            raise ValueError("configuration model prediction source differs")
        return self

    @classmethod
    def from_records(
        cls, intent: ConfigurationModelIntent, outcome: ConfigurationModelOutcome | None
    ) -> Self:
        return cls(
            inference_id=intent.request.inference_id,
            analysis_id=intent.request.analysis_id,
            source=intent.source,
            analysis_sha256=intent.analysis_sha256,
            model_sha256=intent.request.model_sha256,
            total_lines=intent.total_lines,
            created_at=intent.created_at,
            completed_at=outcome.completed_at if outcome else None,
            status=outcome.status if outcome else "pending",
            intent_sha256=fingerprint(intent),
            outcome_sha256=fingerprint(outcome) if outcome else None,
            report=outcome.report if outcome else None,
        )
