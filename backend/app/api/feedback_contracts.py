"""Append-only, analysis-scoped assessments; not patch approvals or ground-truth labels."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

FeedbackVerdict = Literal["confirmed_anomaly", "false_positive", "needs_investigation"]


class SubmitFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    feedback_id: UUID
    analysis_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verdict: FeedbackVerdict
    comment: str = Field(min_length=1, max_length=2000)

    @field_validator("comment")
    @classmethod
    def bounded_comment(cls, value: str) -> str:
        if (
            not value.strip()
            or value != value.strip()
            or any(not character.isprintable() and character not in "\r\n\t" for character in value)
        ):
            raise ValueError("invalid feedback comment")
        return value


class FeedbackRecord(SubmitFeedback):
    version: Literal["finding-feedback-0.1.0"] = "finding-feedback-0.1.0"
    finding_id: UUID
    configuration_id: UUID
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    actor: Literal["shared_service_token"] = "shared_service_token"

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("feedback requires a timezone")
        return value
