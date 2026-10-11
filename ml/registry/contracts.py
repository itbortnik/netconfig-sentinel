"""Numeric model cards describe enrollment, never deployment approval or quality."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, field_validator, model_validator

from ml.evaluation.contracts import Digest, Frozen, Label
from ml.evaluation.metrics import canonical_hash
from ml.training.fixture_contracts import FixtureSourceBinding

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


class FixtureModelCard(Frozen):
    """Explicit source-fixture exposure; never silently added to historical cards."""

    version: Literal["config-model-card-0.2.0"] = "config-model-card-0.2.0"
    kind: Literal["native"] = "native"
    model_sha256: Digest
    training_format: Literal["multitask-training-0.3.0"] = "multitask-training-0.3.0"
    report_sha256: Digest
    encoder_sha256: Digest
    tokenizer_sha256: Digest
    source_manifest_sha256: Digest
    train_fingerprint: Digest
    selection_fingerprint: Digest
    classes: tuple[Label, ...] = Field(min_length=1, max_length=64)
    enabled_heads: dict[str, StrictBool]
    parameter_count: int = Field(ge=1, strict=True)
    trainable_parameters: int = Field(ge=1, strict=True)
    train_examples: int = Field(ge=1, strict=True)
    selection_examples: int = Field(ge=1, strict=True)
    target_semantics: Literal["injected_mutation", "confirmed_anomaly"]
    external_pretraining_exposure: Literal["not_applicable"] = "not_applicable"
    pretraining: FixtureSourceBinding
    physical_pretraining_isolation_proven: Literal[False] = False
    status: Literal["experimental"] = "experimental"
    calibrated: Literal[False] = False
    production_quality_proven: Literal[False] = False
    activated: Literal[False] = False

    @field_validator(
        "physical_pretraining_isolation_proven",
        "calibrated",
        "production_quality_proven",
        "activated",
        mode="before",
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("fixture model experimental/isolation flags must be exact false")
        return value

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (
            self.source_manifest_sha256 != self.pretraining.source_manifest_sha256
            or self.trainable_parameters >= self.parameter_count
            or set(self.enabled_heads) != TASKS
            or len(set(self.classes)) != len(self.classes)
        ):
            raise ValueError("fixture registry card bindings differ")
        return self


type RegistryModelCard = Annotated[ModelCard | FixtureModelCard, Field(discriminator="version")]


class EntryEnvelope(Frozen):
    version: Literal["config-model-entry-0.1.0"] = "config-model-entry-0.1.0"
    card: RegistryModelCard
    sha256: Digest

    @model_validator(mode="after")
    def checksum(self) -> Self:
        if self.sha256 != canonical_hash(self.card.model_dump(mode="json")):
            raise ValueError("registry entry checksum differs")
        return self
