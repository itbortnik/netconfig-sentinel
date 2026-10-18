"""Paired numeric diagnostics with one model, task inventory and runtime."""

from typing import Literal, Self

from pydantic import model_validator

from ml.evaluation.contracts import Frozen
from ml.inference.config_contracts import ConfigurationInferenceReport


class ConfigurationPairReport(Frozen):
    version: Literal["configuration-pair-inference-0.1.0"] = "configuration-pair-inference-0.1.0"
    before: ConfigurationInferenceReport
    after: ConfigurationInferenceReport
    interpretation: Literal["experimental_scores_not_change_validation"] = (
        "experimental_scores_not_change_validation"
    )

    @model_validator(mode="after")
    def same_model_runtime(self) -> Self:
        if (
            self.before.model != self.after.model
            or self.before.runtime_torch_version != self.after.runtime_torch_version
            or self.before.sanitization_version != self.after.sanitization_version
        ):
            raise ValueError(
                "paired inference requires one exact model, task inventory and runtime"
            )
        return self
