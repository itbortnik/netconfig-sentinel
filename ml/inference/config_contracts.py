"""Single-source experimental scores, separate from analysis findings and risk."""

from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from ml.evaluation.contracts import Frozen
from ml.inference.change_contracts import SidePrediction
from ml.registry.contracts import ModelCard


class ConfigurationInferenceReport(Frozen):
    version: Literal["configuration-inference-0.1.0"] = "configuration-inference-0.1.0"
    model: ModelCard
    prediction: SidePrediction
    runtime_torch_version: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9.+_-]+$")
    sanitization_version: Literal["config-sanitizer-0.1.0"] = "config-sanitizer-0.1.0"
    risk_fused: Literal[False] = False
    calibrated: Literal[False] = False
    quality_evaluated: Literal[False] = False
    production_quality_proven: Literal[False] = False

    @field_validator(
        "risk_fused", "calibrated", "quality_evaluated", "production_quality_proven", mode="before"
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("experimental flags must be false")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        card, prediction = self.model, self.prediction
        enabled = card.enabled_heads
        if (
            prediction.model_sha256 != card.model_sha256
            or enabled["anomaly"] != (prediction.anomaly_score is not None)
            or enabled["category"] != (prediction.category_scores is not None)
            or enabled["severity"] != (prediction.severity_scores is not None)
            or enabled["contrastive"] != (prediction.embedding_dimensions > 0)
            or (
                prediction.category_scores is not None
                and set(prediction.category_scores) != set(card.classes)
            )
            or (not enabled["localization"] and any(x is not None for x in prediction.line_scores))
        ):
            raise ValueError("single-source prediction differs from selected model/heads")
        return self
