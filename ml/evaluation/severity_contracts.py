"""Separate five-class anomaly-severity evaluation, without raw configurations.

Hashes bind caller-supplied artifacts; they do not attest annotation truth, source
authorization, actual trained weights or independent evaluation. Exposure gates
for the evaluated cases belong to the fit/evaluate operations, not this schema.
"""

from __future__ import annotations

import math
from typing import Literal, Self

from pydantic import ConfigDict, Field, StrictBool, field_validator, model_validator

from ml.evaluation.contracts import Cohort, Digest, Frozen, Identity, Label, UnitScore

type SeverityLabel = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_CLASSES: tuple[SeverityLabel, ...] = ("info", "low", "medium", "high", "critical")


class _SeverityFrozen(Frozen):
    # Frozen model_copy updates are unvalidated. Revalidate these new models at
    # every nested contract boundary without changing historical 0.1 contracts.
    model_config = ConfigDict(revalidate_instances="always")


def _identity(value: object) -> Identity:
    # Identity is shared with the old protocol, whose instance-revalidation policy
    # remains unchanged. A copied/constructed identity must still satisfy its fields.
    if isinstance(value, Identity):
        value = value.model_dump(warnings=False)
    return Identity.model_validate(value, strict=True)


def _require_disjoint(first: tuple[Identity, ...], second: tuple[Identity, ...]) -> None:
    for field in Identity.model_fields:
        if {getattr(item, field) for item in first} & {getattr(item, field) for item in second}:
            raise ValueError("severity evaluation exposure crosses partition boundaries")


class SeverityEvaluationProtocol(_SeverityFrozen):
    version: Literal["severity-evaluation-0.1.0"] = "severity-evaluation-0.1.0"
    task: Literal["anomaly_severity"] = "anomaly_severity"
    purpose: Literal["independent_test", "validation_diagnostic"]
    target_semantics: Literal["confirmed_anomaly", "injected_mutation", "authored_severity_fixture"]
    score_provenance: Literal["trained_severity_head", "authored_numeric_fixture"]
    model_version: str = Field(min_length=1, max_length=128, strict=True)
    model_sha256: Digest
    tokenizer_sha256: Digest | None = None
    training_report_sha256: Digest | None = None
    dataset_manifest_sha256: Digest
    annotation_manifest_sha256: Digest
    threshold_policy_sha256: Digest
    score_kind: Literal["probability"] = "probability"
    classes: tuple[SeverityLabel, ...] = Field(default=SEVERITY_CLASSES, min_length=5, max_length=5)
    class_thresholds: tuple[UnitScore, ...] = Field(
        default=(0.5, 0.5, 0.5, 0.5, 0.5), min_length=5, max_length=5
    )
    reliability_bins: int = Field(default=10, ge=2, le=50, strict=True)
    train: tuple[Identity, ...] = Field(max_length=20000)
    selection: tuple[Identity, ...] = Field(default=(), max_length=20000)
    calibration: tuple[Identity, ...] = Field(default=(), max_length=20000)
    calibration_sha256: Digest | None = None
    application_input_sha256: Digest | None = None
    reserved_test: tuple[Identity, ...] = Field(min_length=1, max_length=20000)

    @field_validator("train", "selection", "calibration", "reserved_test")
    @classmethod
    def valid_identities(cls, values: tuple[Identity, ...]) -> tuple[Identity, ...]:
        return tuple(_identity(value) for value in values)

    @model_validator(mode="after")
    def provenance_and_exposures(self) -> Self:
        if self.classes != SEVERITY_CLASSES:
            raise ValueError("severity classes must use the fixed ordered five-class catalog")
        trained = self.score_provenance == "trained_severity_head"
        if trained and self.target_semantics == "authored_severity_fixture":
            raise ValueError("authored severity fixture is not trained-head annotation semantics")
        if trained and not self.train:
            raise ValueError("trained severity head requires declared training exposure")
        if (trained and (self.tokenizer_sha256 is None or self.training_report_sha256 is None)) or (
            not trained
            and (self.tokenizer_sha256 is not None or self.training_report_sha256 is not None)
        ):
            raise ValueError("severity score provenance and training artifacts differ")
        if not (
            bool(self.calibration)
            == (self.calibration_sha256 is not None)
            == (self.application_input_sha256 is not None)
        ):
            raise ValueError(
                "calibration exposure, artifact and application input must be bound together"
            )
        groups = (self.train, self.selection, self.calibration, self.reserved_test)
        for index, group in enumerate(groups):
            if len({item.source_sha256 for item in group}) != len(group):
                raise ValueError(
                    "severity exposure source hashes must be unique within a partition"
                )
            for previous in groups[:index]:
                _require_disjoint(previous, group)
        return self


class SeverityEvaluationCase(_SeverityFrozen):
    case_id: Digest
    identity: Identity
    source_review_sha256: Digest
    annotation_sha256: Digest
    prediction_sha256: Digest
    cohort: Cohort
    vendor: Literal["cisco", "juniper"]
    device_role: Label | None = None
    anomaly_truth: StrictBool
    severity_truth: SeverityLabel
    probabilities: tuple[UnitScore, ...] = Field(min_length=5, max_length=5)

    @field_validator("identity", mode="before")
    @classmethod
    def valid_identity(cls, value: object) -> Identity:
        return _identity(value)

    @model_validator(mode="after")
    def known_anomaly_distribution(self) -> Self:
        if self.anomaly_truth is not True:
            raise ValueError("severity evaluation requires positively annotated anomaly truth")
        if not math.isclose(math.fsum(self.probabilities), 1.0, rel_tol=0.0, abs_tol=1e-6):
            raise ValueError("severity probabilities must sum to one without normalization")
        return self


class SeverityEvaluationBatch(_SeverityFrozen):
    protocol: SeverityEvaluationProtocol
    cases: tuple[SeverityEvaluationCase, ...] = Field(min_length=1, max_length=20000)

    @model_validator(mode="after")
    def distinct_cases_and_semantics(self) -> Self:
        if self.protocol.target_semantics == "authored_severity_fixture" and any(
            case.cohort != "synthetic" for case in self.cases
        ):
            raise ValueError(
                "authored severity numeric fixtures belong only to the synthetic cohort"
            )
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("severity case IDs must be unique")
        if len({case.identity.source_sha256 for case in self.cases}) != len(self.cases):
            raise ValueError("severity evaluated source hashes must be unique")
        if self.protocol.target_semantics != "confirmed_anomaly" and any(
            case.cohort == "real_confirmed" for case in self.cases
        ):
            raise ValueError("real-confirmed severity requires confirmed-anomaly annotations")
        if len({case.device_role for case in self.cases}) > 64:
            raise ValueError("severity role slice budget exceeded")
        return self
