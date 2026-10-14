"""Train-fitted localization metadata without importing optional tensor runtimes."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.evaluation.contracts import Digest


class TrainBalancedLocalization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["train-balanced-localization-0.1.0"] = "train-balanced-localization-0.1.0"
    mode: Literal["train_negative_over_positive"] = "train_negative_over_positive"
    reduction: Literal["mean_eligible_lines"] = "mean_eligible_lines"


class FittedLocalizationObjective(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    policy: TrainBalancedLocalization
    train_fingerprint: Digest
    positive_lines: int = Field(ge=1, strict=True)
    negative_lines: int = Field(ge=1, strict=True)
    eligible_lines: int = Field(ge=2, strict=True)
    positive_weight: float = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def bound_counts(self) -> Self:
        if self.eligible_lines != self.positive_lines + self.negative_lines:
            raise ValueError("eligible localization count differs from fitted classes")
        if self.positive_weight != self.negative_lines / self.positive_lines:
            raise ValueError("localization coefficient must be train negative/positive ratio")
        return self
