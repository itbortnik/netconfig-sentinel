"""Numeric model cards describe enrollment, never deployment approval or quality."""

from typing import Literal, Self

from pydantic import Field, StrictBool, model_validator

from ml.evaluation.contracts import Digest, Frozen, Label
from ml.evaluation.metrics import canonical_hash

TASKS = frozenset(("anomaly", "category", "localization", "severity", "contrastive"))


class RegistryManifest(Frozen):
    version: Literal["config-model-registry-0.1.0"] = "config-model-registry-0.1.0"
    automatic_activation: Literal[False] = False
    deployment_approval: Literal[False] = False


class ModelCard(Frozen):
    version: Literal["config-model-card-0.1.0"] = "config-model-card-0.1.0"
    kind: Literal["native", "foundation"]
    model_sha256: Digest
    training_format: Literal[
        "multitask-training-0.1.0", "multitask-training-0.2.0", "foundation-config-transfer-0.1.0"
    ]
    report_sha256: Digest
    encoder_sha256: Digest
    tokenizer_sha256: Digest
    source_manifest_sha256: Digest | None
    train_fingerprint: Digest
    selection_fingerprint: Digest
    classes: tuple[Label, ...] = Field(min_length=1, max_length=64)
    enabled_heads: dict[str, StrictBool]
    parameter_count: int = Field(ge=1, strict=True)
    trainable_parameters: int = Field(ge=1, strict=True)
    train_examples: int = Field(ge=1, strict=True)
    selection_examples: int = Field(ge=1, strict=True)
    target_semantics: Literal["injected_mutation", "confirmed_anomaly"]
    external_pretraining_exposure: Literal["unknown", "not_applicable"]
    status: Literal["experimental"] = "experimental"
    calibrated: Literal[False] = False
    production_quality_proven: Literal[False] = False
    activated: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self) -> Self:
        foundation = self.kind == "foundation"
        if (
            foundation != (self.training_format == "foundation-config-transfer-0.1.0")
            or foundation != (self.external_pretraining_exposure == "unknown")
            or (self.training_format == "multitask-training-0.1.0")
            != (self.source_manifest_sha256 is None)
            or self.trainable_parameters >= self.parameter_count
            or set(self.enabled_heads) != TASKS
            or len(set(self.classes)) != len(self.classes)
        ):
            raise ValueError("registry model card bindings differ")
        return self


class EntryEnvelope(Frozen):
    version: Literal["config-model-entry-0.1.0"] = "config-model-entry-0.1.0"
    card: ModelCard
    sha256: Digest

    @model_validator(mode="after")
    def checksum(self) -> Self:
        if self.sha256 != canonical_hash(self.card.model_dump(mode="json")):
            raise ValueError("registry entry checksum differs")
        return self
