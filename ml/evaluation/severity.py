"""Offline severity softmax calibration; no fused-risk or model-quality promotion."""

from __future__ import annotations

import math
from typing import Literal

import numpy as np
from pydantic import Field, StrictInt, model_validator

from ml.evaluation.calibration import EPSILON, CalibrationPolicy, Temperature
from ml.evaluation.contracts import COHORTS, Digest, Frozen, Identity, UnitScore
from ml.evaluation.metrics import (
    BinaryMetrics,
    CalibrationMetrics,
    _require_disjoint,
    binary_metrics,
    calibration_metrics,
    canonical_hash,
)
from ml.evaluation.severity_contracts import (
    SEVERITY_CLASSES,
    SeverityEvaluationBatch,
    SeverityEvaluationCase,
    SeverityEvaluationProtocol,
    SeverityLabel,
)


class SeverityOperatingPoint(Frozen):
    label: SeverityLabel
    threshold: UnitScore
    positive_cases: StrictInt = Field(ge=1)
    negative_cases: StrictInt = Field(ge=1)
    fitting_f1: UnitScore
    fitting_precision: UnitScore


class SeverityCalibrationArtifact(Frozen):
    version: Literal["severity-calibration-0.1.0"] = "severity-calibration-0.1.0"
    method: Literal["shared-multiclass-temperature-grid"] = "shared-multiclass-temperature-grid"
    numerical_policy: Literal["preserve-zero-endpoints-nll-clip-1e-12"] = (
        "preserve-zero-endpoints-nll-clip-1e-12"
    )
    protocol: SeverityEvaluationProtocol
    policy: CalibrationPolicy
    calibration_input_sha256: Digest
    exposure: tuple[Identity, ...] = Field(min_length=1, max_length=20000)
    temperature: Temperature
    original_multiclass_nll: float = Field(ge=0)
    calibrated_multiclass_nll: float = Field(ge=0)
    operating_points: tuple[SeverityOperatingPoint, ...] = Field(min_length=5, max_length=5)
    fit_cohort_counts: dict[str, StrictInt]
    risk_fused: Literal[False] = False
    online_risk_updated: Literal[False] = False
    production_quality_proven: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self) -> SeverityCalibrationArtifact:
        if self.protocol.purpose != "validation_diagnostic" or (
            self.protocol.calibration_sha256 is not None
            or self.temperature not in self.policy.temperatures
            or tuple(point.label for point in self.operating_points) != SEVERITY_CLASSES
            or len({item.source_sha256 for item in self.exposure}) != len(self.exposure)
        ):
            raise ValueError("severity calibration protocol or class binding differs")
        if self.calibrated_multiclass_nll > self.original_multiclass_nll + 1e-12:
            raise ValueError("shared temperature worsens fitting multiclass NLL")
        if (
            not self.fit_cohort_counts
            or set(self.fit_cohort_counts) - set(COHORTS)
            or any(type(value) is not int or value < 1 for value in self.fit_cohort_counts.values())
            or sum(self.fit_cohort_counts.values()) != len(self.exposure)
        ):
            raise ValueError("severity fitting cohort counts differ")
        for group in (self.protocol.train, self.protocol.selection, self.protocol.reserved_test):
            _require_disjoint(group, self.exposure)
        for point in self.operating_points:
            if point.threshold not in self.policy.thresholds or (
                min(point.positive_cases, point.negative_cases) < self.policy.minimum_class_support
                or point.positive_cases + point.negative_cases != len(self.exposure)
            ):
                raise ValueError("severity threshold support differs from policy")
        return self


class SeveritySliceMetrics(Frozen):
    cases: int
    declared_unique_devices: int
    classes: tuple[BinaryMetrics, ...]
    threshold_macro_f1: float | None
    threshold_macro_f1_defined_classes: int
    argmax_accuracy: float
    argmax_confusion_matrix: tuple[tuple[int, ...], ...]
    multiclass_nll: float
    multiclass_brier: float
    top_label_reliability: CalibrationMetrics


class SeverityCohortMetrics(Frozen):
    status: Literal["available", "missing"]
    summary: SeveritySliceMetrics | None
    unseen_sites: SeveritySliceMetrics | None
    by_vendor: dict[str, SeveritySliceMetrics | None]
    by_role: dict[str, SeveritySliceMetrics]


class SeverityReportProtocol(Frozen):
    """Aggregate model/score bindings, without source or entity grouping identities."""

    purpose: Literal["independent_test", "validation_diagnostic"]
    target_semantics: Literal["confirmed_anomaly", "injected_mutation", "authored_severity_fixture"]
    score_provenance: Literal["trained_severity_head", "authored_numeric_fixture"]
    model_version: str
    model_sha256: Digest
    tokenizer_sha256: Digest | None
    training_report_sha256: Digest | None
    dataset_manifest_sha256: Digest
    annotation_manifest_sha256: Digest
    threshold_policy_sha256: Digest
    class_thresholds: tuple[UnitScore, ...]
    reliability_bins: int
    calibration_sha256: Digest | None
    application_input_sha256: Digest | None
    exposure_counts: dict[str, int]


class SeverityEvaluationReport(Frozen):
    version: Literal["severity-metrics-0.1.0"] = "severity-metrics-0.1.0"
    task: Literal["anomaly_severity"] = "anomaly_severity"
    classes: tuple[SeverityLabel, ...] = SEVERITY_CLASSES
    input_sha256: Digest
    protocol_sha256: Digest
    protocol: SeverityReportProtocol
    partition: Literal["test", "diagnostic"]
    identity_holdout_checked: bool
    cohorts: dict[str, SeverityCohortMetrics]
    risk_fused: Literal[False] = False
    online_risk_updated: Literal[False] = False
    production_quality_proven: Literal[False] = False
    physical_independence_proven: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Severity is a five-class anomaly classifier target, not four-level fused network risk.",
        "Source, annotation, prediction and grouping hashes bind supplied records; they do not "
        "authenticate labels, rights, physical independence or model execution.",
        "OVR thresholds are independent offline signals; multiple or no classes can trigger.",
        "Argmax classification and thresholded OVR metrics use different decision rules.",
        "No pooled metric combines synthetic, laboratory and confirmed-real cohorts.",
        "Authored numeric fixture probabilities are not trained-head predictions.",
        "A fitting-partition NLL improvement does not qualify held-out or real calibration.",
    )


def _protocol_data(protocol: SeverityEvaluationProtocol) -> dict[str, object]:
    data = protocol.model_dump(mode="json", warnings=False)
    for name in ("train", "selection", "calibration", "reserved_test"):
        data[name] = sorted(data[name], key=canonical_hash)
    return data


def severity_batch_identity(batch: SeverityEvaluationBatch) -> str:
    batch = SeverityEvaluationBatch.model_validate(batch.model_dump(warnings=False))
    return canonical_hash(
        {
            "protocol": _protocol_data(batch.protocol),
            "cases": [
                case.model_dump(mode="json", warnings=False)
                for case in sorted(batch.cases, key=lambda case: case.case_id)
            ],
        }
    )


def _check_exposure(batch: SeverityEvaluationBatch) -> set[str]:
    protocol = batch.protocol
    identities = tuple(case.identity for case in batch.cases)
    _require_disjoint(protocol.train, identities)
    if protocol.purpose == "independent_test":
        for group in (protocol.selection, protocol.calibration):
            _require_disjoint(group, identities)
        if sorted(map(canonical_hash, [item.model_dump(mode="json") for item in identities])) != (
            sorted(
                map(
                    canonical_hash,
                    [item.model_dump(mode="json") for item in protocol.reserved_test],
                )
            )
        ):
            raise ValueError("severity test identities differ from the complete reservation")
    else:
        _require_disjoint(protocol.reserved_test, identities)
    return {
        item.site_key
        for group in (protocol.train, protocol.selection, protocol.calibration)
        for item in group
    }


def _scaled(probabilities: np.ndarray, temperature: float) -> np.ndarray:
    if temperature == 1.0:
        return probabilities.copy()
    with np.errstate(divide="ignore"):
        logits = np.log(probabilities) / temperature
    logits -= logits.max(axis=1, keepdims=True)
    output = np.exp(logits)
    return output / output.sum(axis=1, keepdims=True)


def _nll(truth: np.ndarray, probabilities: np.ndarray) -> float:
    selected = probabilities[np.arange(len(truth)), truth]
    return float(-np.log(np.clip(selected, EPSILON, 1.0)).mean())


def _summary(
    cases: tuple[SeverityEvaluationCase, ...], protocol: SeverityEvaluationProtocol
) -> SeveritySliceMetrics:
    truth = np.asarray([SEVERITY_CLASSES.index(case.severity_truth) for case in cases])
    probabilities = np.asarray([case.probabilities for case in cases], dtype=np.float64)
    predicted = probabilities.argmax(axis=1)
    matrix = [[0] * 5 for _ in range(5)]
    for actual, selected in zip(truth, predicted, strict=True):
        matrix[int(actual)][int(selected)] += 1
    classes = tuple(
        binary_metrics(
            label,
            [case.severity_truth == label for case in cases],
            [case.probabilities[index] for case in cases],
            protocol.class_thresholds[index],
            protocol,
        )
        for index, label in enumerate(SEVERITY_CLASSES)
    )
    f1s = [item.f1 for item in classes if item.f1 is not None]
    return SeveritySliceMetrics(
        cases=len(cases),
        declared_unique_devices=len({case.identity.device_key for case in cases}),
        classes=classes,
        threshold_macro_f1=sum(f1s) / len(f1s) if f1s else None,
        threshold_macro_f1_defined_classes=len(f1s),
        argmax_accuracy=float((truth == predicted).mean()),
        argmax_confusion_matrix=tuple(tuple(row) for row in matrix),
        multiclass_nll=_nll(truth, probabilities),
        multiclass_brier=float(((probabilities - np.eye(5)[truth]) ** 2).sum(axis=1).mean()),
        top_label_reliability=calibration_metrics(
            [bool(actual == selected) for actual, selected in zip(truth, predicted, strict=True)],
            [float(value) for value in probabilities.max(axis=1)],
            protocol.reliability_bins,
        ),
    )


def evaluate_severity(batch: SeverityEvaluationBatch) -> SeverityEvaluationReport:
    batch = SeverityEvaluationBatch.model_validate(batch.model_dump(warnings=False))
    exposed_sites = _check_exposure(batch)
    cases = tuple(sorted(batch.cases, key=lambda case: case.case_id))
    cohorts = {}
    for cohort in COHORTS:
        rows = tuple(case for case in cases if case.cohort == cohort)
        unseen = tuple(case for case in rows if case.identity.site_key not in exposed_sites)
        cohorts[cohort] = SeverityCohortMetrics(
            status="available" if rows else "missing",
            summary=_summary(rows, batch.protocol) if rows else None,
            unseen_sites=_summary(unseen, batch.protocol) if unseen else None,
            by_vendor={
                vendor: _summary(selected, batch.protocol) if selected else None
                for vendor in ("cisco", "juniper")
                for selected in (tuple(case for case in rows if case.vendor == vendor),)
            },
            by_role={
                role: _summary(
                    tuple(case for case in rows if (case.device_role or "<unrecorded>") == role),
                    batch.protocol,
                )
                for role in sorted({case.device_role or "<unrecorded>" for case in rows})
            },
        )
    public_protocol = _protocol_data(batch.protocol)
    exposure_counts = {}
    for name in ("train", "selection", "calibration", "reserved_test"):
        exposure_counts[name] = len(getattr(batch.protocol, name))
        public_protocol.pop(name)
    for name in ("version", "task", "score_kind", "classes"):
        public_protocol.pop(name)
    return SeverityEvaluationReport(
        input_sha256=severity_batch_identity(batch),
        protocol_sha256=canonical_hash(_protocol_data(batch.protocol)),
        protocol=SeverityReportProtocol.model_validate(
            {**public_protocol, "exposure_counts": exposure_counts}
        ),
        partition="test" if batch.protocol.purpose == "independent_test" else "diagnostic",
        identity_holdout_checked=batch.protocol.purpose == "independent_test",
        cohorts=cohorts,
    )


def fit_severity_calibration(
    batch: SeverityEvaluationBatch, *, policy: CalibrationPolicy | None = None
) -> SeverityCalibrationArtifact:
    batch = SeverityEvaluationBatch.model_validate(batch.model_dump(warnings=False))
    policy = CalibrationPolicy.model_validate(
        (policy or CalibrationPolicy()).model_dump(warnings=False)
    )
    if batch.protocol.purpose != "validation_diagnostic" or (
        batch.protocol.calibration_sha256 is not None
    ):
        raise ValueError("fit only fresh separate severity calibration diagnostics")
    _check_exposure(batch)
    rows = tuple(sorted(batch.cases, key=lambda case: case.case_id))
    exposure = tuple(case.identity for case in rows)
    _require_disjoint(batch.protocol.selection, exposure)
    truth = np.asarray([SEVERITY_CLASSES.index(case.severity_truth) for case in rows])
    probabilities = np.asarray([case.probabilities for case in rows], dtype=np.float64)
    transformed = {
        temperature: _scaled(probabilities, temperature) for temperature in policy.temperatures
    }
    losses = {temperature: _nll(truth, scores) for temperature, scores in transformed.items()}
    temperature = min(
        policy.temperatures,
        key=lambda item: (round(losses[item], 15), abs(math.log(item)), item),
    )
    points = []
    for index, label in enumerate(SEVERITY_CLASSES):
        actual = truth == index
        positives, negatives = int(actual.sum()), int((~actual).sum())
        if min(positives, negatives) < policy.minimum_class_support:
            raise ValueError(
                "all severity classes require sufficient positive and negative support"
            )
        metrics = {}
        for threshold in policy.thresholds:
            predicted = transformed[temperature][:, index] > threshold
            tp, fp, fn = (
                int((actual & predicted).sum()),
                int((~actual & predicted).sum()),
                int((actual & ~predicted).sum()),
            )
            metrics[threshold] = (2 * tp / (2 * tp + fp + fn), tp / (tp + fp) if tp + fp else 0.0)
        threshold = max(policy.thresholds, key=lambda item: (*metrics[item], item))
        points.append(
            SeverityOperatingPoint(
                label=label,
                threshold=threshold,
                positive_cases=positives,
                negative_cases=negatives,
                fitting_f1=metrics[threshold][0],
                fitting_precision=metrics[threshold][1],
            )
        )
    return SeverityCalibrationArtifact(
        protocol=SeverityEvaluationProtocol.model_validate(_protocol_data(batch.protocol)),
        policy=policy,
        calibration_input_sha256=severity_batch_identity(batch),
        exposure=exposure,
        temperature=temperature,
        original_multiclass_nll=losses[1.0],
        calibrated_multiclass_nll=losses[temperature],
        operating_points=tuple(points),
        fit_cohort_counts={
            cohort: sum(case.cohort == cohort for case in rows)
            for cohort in sorted({case.cohort for case in rows})
        },
    )


def severity_artifact_identity(artifact: SeverityCalibrationArtifact) -> str:
    artifact = SeverityCalibrationArtifact.model_validate(artifact.model_dump(warnings=False))
    return canonical_hash(artifact.model_dump(mode="json", warnings=False))


def _binding(protocol: SeverityEvaluationProtocol) -> dict[str, object]:
    data = _protocol_data(protocol)
    for field in (
        "purpose",
        "class_thresholds",
        "threshold_policy_sha256",
        "calibration_sha256",
        "calibration",
        "application_input_sha256",
    ):
        data.pop(field)
    return data


def apply_severity_calibration(
    batch: SeverityEvaluationBatch,
    artifact: SeverityCalibrationArtifact,
    *,
    calibration_input: SeverityEvaluationBatch,
) -> SeverityEvaluationBatch:
    """Recheck retained fitting data, then transform evaluation scores without fitting it."""
    batch = SeverityEvaluationBatch.model_validate(batch.model_dump(warnings=False))
    artifact = SeverityCalibrationArtifact.model_validate(artifact.model_dump(warnings=False))
    if batch.protocol.calibration_sha256 is not None:
        raise ValueError("severity scores already carry calibration")
    if _binding(batch.protocol) != _binding(artifact.protocol):
        raise ValueError("severity calibration model/corpus/exposure binding differs")
    if fit_severity_calibration(calibration_input, policy=artifact.policy) != artifact:
        raise ValueError("retained severity fitting data does not reproduce the artifact")
    data = batch.model_dump(warnings=False)
    probabilities = np.asarray([case.probabilities for case in batch.cases], dtype=np.float64)
    transformed = _scaled(probabilities, artifact.temperature)
    data["protocol"].update(
        calibration_sha256=severity_artifact_identity(artifact),
        calibration=tuple(item.model_dump() for item in artifact.exposure),
        application_input_sha256=severity_batch_identity(batch),
        class_thresholds=tuple(point.threshold for point in artifact.operating_points),
        threshold_policy_sha256=canonical_hash(
            [point.model_dump(mode="json") for point in artifact.operating_points]
        ),
    )
    for row, scores in zip(data["cases"], transformed, strict=True):
        row["probabilities"] = tuple(float(value) for value in scores)
    result = SeverityEvaluationBatch.model_validate(data)
    evaluate_severity(result)
    return result
