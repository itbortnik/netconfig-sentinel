"""Bounded binary temperature/threshold fit on a separate calibration partition."""

from __future__ import annotations

import math
from typing import Annotated, Literal

import numpy as np
from pydantic import Field, StrictInt, model_validator

from ml.evaluation.contracts import EvaluationBatch, EvaluationProtocol, Frozen, Identity, UnitScore
from ml.evaluation.metrics import _require_disjoint, canonical_hash, evaluate

EPSILON = 1e-12
Temperature = Annotated[float, Field(ge=0.1, le=10, strict=True)]


class CalibrationPolicy(Frozen):
    temperatures: tuple[Temperature, ...] = (0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0)
    thresholds: tuple[UnitScore, ...] = tuple(index / 20 for index in range(21))
    minimum_class_support: int = Field(default=10, ge=1, le=10000, strict=True)

    @model_validator(mode="after")
    def bounded_grid(self) -> CalibrationPolicy:
        if (
            not self.temperatures
            or len(self.temperatures) > 100
            or (self.temperatures != tuple(sorted(set(self.temperatures))))
            or any(
                not math.isfinite(value) or not 0.1 <= value <= 10 for value in self.temperatures
            )
        ):
            raise ValueError("temperature grid must be sorted, unique and bounded")
        if 1.0 not in self.temperatures:
            raise ValueError("temperature grid must include the identity transform")
        if (
            not self.thresholds
            or len(self.thresholds) > 101
            or (self.thresholds != tuple(sorted(set(self.thresholds))))
        ):
            raise ValueError("threshold grid must be sorted, unique and bounded")
        return self


class ChannelCalibration(Frozen):
    label: str
    temperature: Temperature
    threshold: UnitScore
    positive_cases: StrictInt = Field(ge=1)
    negative_cases: StrictInt = Field(ge=1)
    original_nll: float = Field(ge=0)
    calibrated_nll: float = Field(ge=0)
    selection_f1: UnitScore


class CalibrationArtifact(Frozen):
    version: Literal["binary-temperature-grid-0.1.0"] = "binary-temperature-grid-0.1.0"
    policy: CalibrationPolicy
    protocol: EvaluationProtocol
    calibration_input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exposure: tuple[Identity, ...] = Field(min_length=1, max_length=20000)
    channels: tuple[ChannelCalibration, ...] = Field(min_length=2, max_length=65)
    fit_cohort_counts: dict[str, StrictInt]
    independent_test: Literal[False] = False
    production_quality_proven: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self) -> CalibrationArtifact:
        if self.protocol.purpose != "validation_diagnostic" or (
            self.protocol.score_kind != "probability"
            or self.protocol.calibration_sha256 is not None
        ):
            raise ValueError("calibration requires a fresh probability diagnostic protocol")
        if tuple(channel.label for channel in self.channels) != (
            "__detection__",
            *self.protocol.classes,
        ):
            raise ValueError("calibration channels must follow the complete class catalog")
        if len({item.source_sha256 for item in self.exposure}) != len(self.exposure):
            raise ValueError("calibration configuration identities must be unique")
        if (
            set(self.fit_cohort_counts) - {"synthetic", "laboratory", "real_confirmed"}
            or any(type(count) is not int or count < 1 for count in self.fit_cohort_counts.values())
            or sum(self.fit_cohort_counts.values()) != len(self.exposure)
        ):
            raise ValueError("calibration cohort counts must match exposure")
        for channel in self.channels:
            if (
                channel.temperature not in self.policy.temperatures
                or (channel.threshold not in self.policy.thresholds)
                or min(channel.positive_cases, channel.negative_cases)
                < (self.policy.minimum_class_support)
                or channel.positive_cases + channel.negative_cases != len(self.exposure)
            ):
                raise ValueError("calibration channels must match policy and support")
            if channel.calibrated_nll > channel.original_nll + 1e-12:
                raise ValueError("calibration must not worsen fitting-partition NLL")
        _require_disjoint(self.protocol.train, self.exposure)
        _require_disjoint(self.protocol.selection, self.exposure)
        return self


def _scaled(scores: list[float], temperature: float) -> list[float]:
    original = np.asarray(scores, dtype=np.float64)
    clipped = np.clip(original, EPSILON, 1 - EPSILON)
    logits = (np.log(clipped) - np.log1p(-clipped)) / temperature
    values = np.exp(-np.logaddexp(0, -logits))
    # Endpoint probabilities remain endpoints; no fabricated finite logit evidence.
    values[original == 0], values[original == 1] = 0, 1
    return [float(value) for value in values]


def _nll(truth: list[bool], probabilities: list[float]) -> float:
    scores = np.clip(np.asarray(probabilities), EPSILON, 1 - EPSILON)
    labels = np.asarray(truth)
    return float(np.mean(np.where(labels, -np.log(scores), -np.log1p(-scores))))


def _channel(
    label: str,
    truth: list[bool],
    scores: list[float],
    policy: CalibrationPolicy,
) -> ChannelCalibration:
    positives, negatives = sum(truth), len(truth) - sum(truth)
    if min(positives, negatives) < policy.minimum_class_support:
        raise ValueError("every calibration channel requires sufficient positive/negative support")
    values = {temperature: _scaled(scores, temperature) for temperature in policy.temperatures}
    temperature = min(
        policy.temperatures,
        key=lambda value: (
            round(_nll(truth, values[value]), 15),
            abs(math.log(value)),
            value,
        ),
    )
    probabilities = values[temperature]
    metrics = {}
    for threshold in policy.thresholds:
        predicted = [value > threshold for value in probabilities]
        tp = sum(label and selected for label, selected in zip(truth, predicted, strict=True))
        fp = sum(not label and selected for label, selected in zip(truth, predicted, strict=True))
        fn = positives - tp
        metrics[threshold] = (2 * tp / (2 * tp + fp + fn), tp / (tp + fp) if tp + fp else 0)
    threshold = max(policy.thresholds, key=lambda value: (*metrics[value], value))
    return ChannelCalibration(
        label=label,
        temperature=temperature,
        threshold=threshold,
        positive_cases=positives,
        negative_cases=negatives,
        original_nll=_nll(truth, scores),
        calibrated_nll=_nll(truth, probabilities),
        selection_f1=metrics[threshold][0],
    )


def fit_calibration(
    batch: EvaluationBatch,
    *,
    policy: CalibrationPolicy | None = None,
) -> CalibrationArtifact:
    batch = EvaluationBatch.model_validate(batch.model_dump())
    policy = CalibrationPolicy.model_validate((policy or CalibrationPolicy()).model_dump())
    if batch.protocol.purpose != "validation_diagnostic" or (
        batch.protocol.score_kind != "probability" or batch.protocol.calibration_sha256 is not None
    ):
        raise ValueError("fit only fresh probability scores from a calibration diagnostic")
    rows = sorted(batch.cases, key=lambda case: case.case_id)
    exposure = tuple(case.identity for case in rows)
    _require_disjoint(batch.protocol.selection, exposure)
    report = evaluate(batch)
    channels = [
        _channel(
            "__detection__",
            [case.anomaly_truth for case in rows],
            [case.detection_score for case in rows],
            policy,
        )
    ]
    for index, label in enumerate(batch.protocol.classes):
        channels.append(
            _channel(
                label,
                [label in case.category_truth for case in rows],
                [case.category_scores[index] for case in rows],
                policy,
            )
        )
    protocol_data = batch.protocol.model_dump()
    for group in ("train", "selection", "calibration"):
        protocol_data[group] = tuple(sorted(protocol_data[group], key=canonical_hash))
    return CalibrationArtifact(
        policy=policy,
        protocol=EvaluationProtocol.model_validate(protocol_data),
        calibration_input_sha256=report.input_sha256,
        exposure=exposure,
        channels=tuple(channels),
        fit_cohort_counts={
            origin: sum(case.cohort == origin for case in rows)
            for origin in sorted({case.cohort for case in rows})
        },
    )


def artifact_identity(artifact: CalibrationArtifact) -> str:
    artifact = CalibrationArtifact.model_validate(artifact.model_dump())
    return canonical_hash(artifact.model_dump(mode="json"))


def _binding(protocol: EvaluationProtocol) -> dict[str, object]:
    data = protocol.model_dump(mode="json")
    for group in ("train", "selection"):
        data[group] = sorted(data[group], key=canonical_hash)
    for key in (
        "purpose",
        "calibration",
        "calibration_sha256",
        "detection_threshold",
        "category_thresholds",
        "threshold_policy_sha256",
    ):
        data.pop(key)
    return data


def apply_calibration(batch: EvaluationBatch, artifact: CalibrationArtifact) -> EvaluationBatch:
    """Transform probabilities only; never labels, versions, findings or online risk."""
    batch = EvaluationBatch.model_validate(batch.model_dump())
    artifact = CalibrationArtifact.model_validate(artifact.model_dump())
    if batch.protocol.calibration_sha256 is not None:
        raise ValueError("scores already have a recorded calibration")
    if _binding(batch.protocol) != _binding(artifact.protocol):
        raise ValueError("calibration binding differs from model/corpus/exposure protocol")
    channels = artifact.channels
    data = batch.model_dump()
    data["protocol"].update(
        calibration_sha256=artifact_identity(artifact),
        calibration=tuple(identity.model_dump() for identity in artifact.exposure),
        detection_threshold=channels[0].threshold,
        category_thresholds=tuple(channel.threshold for channel in channels[1:]),
        threshold_policy_sha256=canonical_hash([channel.model_dump() for channel in channels]),
    )
    for row in data["cases"]:
        row["detection_score"] = _scaled([row["detection_score"]], channels[0].temperature)[0]
        row["category_scores"] = tuple(
            _scaled([score], channel.temperature)[0]
            for score, channel in zip(row["category_scores"], channels[1:], strict=True)
        )
    calibrated = EvaluationBatch.model_validate(data)
    evaluate(calibrated)  # The updated calibration exposure participates in the holdout gate.
    return calibrated
