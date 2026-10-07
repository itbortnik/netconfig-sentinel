"""Paired anomaly-only comparisons: one shared truth table, no fabricated baseline heads."""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import Field, model_validator

from ml.evaluation.contracts import (
    COHORTS,
    Cohort,
    Digest,
    EvaluationProtocol,
    Frozen,
    Identity,
    Label,
    UnitScore,
)
from ml.evaluation.metrics import (
    BinaryMetrics,
    LatencyMetrics,
    _require_disjoint,
    binary_metrics,
    canonical_hash,
)


class ComparisonTruth(Frozen):
    case_id: Digest
    identity: Identity
    source_review_sha256: Digest
    annotation_sha256: Digest
    cohort: Cohort
    vendor: Literal["cisco", "juniper"]
    device_role: Label | None = None
    anomaly_truth: bool = Field(strict=True)


class DetectionPrediction(Frozen):
    case_id: Digest
    source_sha256: Digest
    score: UnitScore
    analysis_seconds: float | None = Field(default=None, ge=0, le=86400, strict=True)


class DetectorRun(Frozen):
    label: Label
    role: Literal["baseline", "candidate"]
    protocol: EvaluationProtocol
    predictions: tuple[DetectionPrediction, ...] = Field(min_length=1, max_length=20000)


class ComparisonInput(Frozen):
    version: Literal["paired-detection-input-0.1.0"] = "paired-detection-input-0.1.0"
    truth: tuple[ComparisonTruth, ...] = Field(min_length=1, max_length=20000)
    runs: tuple[DetectorRun, ...] = Field(min_length=2, max_length=8)

    @model_validator(mode="after")
    def alignment(self) -> Self:
        if (
            len(self.truth) * len(self.runs) > 100000
            or len({row.case_id for row in self.truth}) != len(self.truth)
            or len({row.identity.source_sha256 for row in self.truth}) != len(self.truth)
            or len({row.device_role for row in self.truth}) > 64
        ):
            raise ValueError("comparison truth is duplicate or exceeds budget")
        if len({run.label for run in self.runs}) != len(self.runs) or (
            len({run.protocol.model_sha256 for run in self.runs}) != len(self.runs)
            or sum(run.role == "baseline" for run in self.runs) != 1
        ):
            raise ValueError("comparison requires distinct models and exactly one baseline")
        expected = {row.case_id: row.identity.source_sha256 for row in self.truth}
        common = self.runs[0].protocol
        for run in self.runs:
            protocol = run.protocol
            if any(
                getattr(protocol, name) != getattr(common, name)
                for name in (
                    "dataset_manifest_sha256",
                    "purpose",
                    "target_semantics",
                    "latency_scope",
                )
            ):
                raise ValueError(
                    "comparison protocols have different source/partition/truth/latency"
                )
            if (
                len(run.predictions) != len(expected)
                or {row.case_id: row.source_sha256 for row in run.predictions} != expected
            ):
                raise ValueError("comparison requires every exact shared case, not an intersection")
            if any(row.cohort == "real_confirmed" for row in self.truth) and (
                protocol.target_semantics != "confirmed_anomaly"
            ):
                raise ValueError("real comparison cannot use injected mutation truth")
        return self


class Difference(Frozen):
    f1: float | None
    average_precision: float | None
    pr_auc_trapezoidal: float | None
    false_positives_per_device: float
    mean_seconds: float | None


class DetectorMetrics(Frozen):
    detection: BinaryMetrics
    false_positives_per_device: float
    latency: LatencyMetrics
    difference_from_baseline: Difference | None


class ComparisonSlice(Frozen):
    configurations: int = Field(ge=1)
    unique_devices: int = Field(ge=1)
    models: dict[str, DetectorMetrics]


class ComparisonCohort(Frozen):
    status: Literal["available", "missing"]
    summary: ComparisonSlice | None
    common_unseen_sites: ComparisonSlice | None
    by_vendor: dict[str, ComparisonSlice | None]
    by_role: dict[str, ComparisonSlice]


class DetectorBinding(Frozen):
    role: Literal["baseline", "candidate"]
    model_version: str
    model_sha256: Digest
    tokenizer_sha256: Digest | None
    protocol_sha256: Digest
    threshold_policy_sha256: Digest
    detection_threshold: UnitScore
    score_kind: Literal["probability", "ranking"]
    calibration_sha256: Digest | None


class DetectionComparisonReport(Frozen):
    version: Literal["paired-detection-report-0.1.0"] = "paired-detection-report-0.1.0"
    input_sha256: Digest
    truth_sha256: Digest
    dataset_manifest_sha256: Digest
    purpose: Literal["independent_test", "validation_diagnostic"]
    target_semantics: Literal["confirmed_anomaly", "injected_mutation"]
    latency_scope: Literal["producer_measured", "parsing_and_inference"]
    baseline: Label
    models: dict[str, DetectorBinding]
    cohorts: dict[str, ComparisonCohort]
    local_entity_exposure_checked: Literal[True] = True
    external_pretraining_isolation_proven: Literal[False] = False
    production_quality_proven: Literal[False] = False
    significance_tested: Literal[False] = False
    risk_updated: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Caller-supplied authorization, truth and grouping are not independently attested.",
        "All models score the same complete source-bound truth table; no row intersection.",
        "Anomaly-only comparison never invents baseline category, localization or unknown heads.",
        "Thresholds and score kinds are recorded per model; deltas are not a universal winner.",
        "No significance intervals treat formatting views as independent networks.",
        "Local exposure checks do not establish external pretraining corpus isolation.",
        "False positives per device count configuration alerts, not deduplicated incidents.",
        "Latency deltas require the same measured cases; cold start and I/O may be excluded.",
    )


def _canonical_input(value: ComparisonInput) -> dict[str, Any]:
    payload = value.model_dump(mode="json")
    payload["truth"] = sorted(payload["truth"], key=lambda row: row["case_id"])
    payload["runs"] = sorted(payload["runs"], key=lambda run: run["label"])
    for run in payload["runs"]:
        run["predictions"] = sorted(run["predictions"], key=lambda row: row["case_id"])
        for name in ("train", "selection", "calibration"):
            run["protocol"][name] = sorted(run["protocol"][name], key=canonical_hash)
    return payload


def _latency(values: tuple[float | None, ...]) -> LatencyMetrics:
    import numpy as np

    measured = tuple(value for value in values if value is not None)
    return LatencyMetrics(
        measured_cases=len(measured),
        missing_cases=len(values) - len(measured),
        mean_seconds=float(np.mean(measured)) if measured else None,
        median_seconds=float(np.median(measured)) if measured else None,
        p95_seconds=float(np.percentile(measured, 95)) if measured else None,
        max_seconds=max(measured) if measured else None,
    )


def _difference(first: float | None, second: float | None) -> float | None:
    return first - second if first is not None and second is not None else None


def _summary(
    rows: tuple[ComparisonTruth, ...],
    runs: tuple[DetectorRun, ...],
    baseline: str,
) -> ComparisonSlice:
    models = {}
    measured_cases = {}
    devices = len({row.identity.device_key for row in rows})
    for run in runs:
        predictions = {row.case_id: row for row in run.predictions}
        measured_cases[run.label] = {
            row.case_id for row in rows if predictions[row.case_id].analysis_seconds is not None
        }
        metrics = binary_metrics(
            "anomaly",
            tuple(row.anomaly_truth for row in rows),
            tuple(predictions[row.case_id].score for row in rows),
            run.protocol.detection_threshold,
            run.protocol,
        )
        models[run.label] = DetectorMetrics(
            detection=metrics,
            false_positives_per_device=metrics.false_positive / devices,
            latency=_latency(tuple(predictions[row.case_id].analysis_seconds for row in rows)),
            difference_from_baseline=None,
        )
    control = models[baseline]
    for label, result in tuple(models.items()):
        if label != baseline:
            models[label] = result.model_copy(
                update={
                    "difference_from_baseline": Difference(
                        f1=_difference(result.detection.f1, control.detection.f1),
                        average_precision=_difference(
                            result.detection.average_precision, control.detection.average_precision
                        ),
                        pr_auc_trapezoidal=_difference(
                            result.detection.pr_auc_trapezoidal,
                            control.detection.pr_auc_trapezoidal,
                        ),
                        false_positives_per_device=result.false_positives_per_device
                        - control.false_positives_per_device,
                        mean_seconds=_difference(
                            result.latency.mean_seconds, control.latency.mean_seconds
                        )
                        if measured_cases[label] == measured_cases[baseline]
                        else None,
                    )
                }
            )
    return ComparisonSlice(configurations=len(rows), unique_devices=devices, models=models)


def compare_detectors(value: ComparisonInput) -> DetectionComparisonReport:
    value = ComparisonInput.model_validate(value.model_dump())
    truth = tuple(sorted(value.truth, key=lambda row: row.case_id))
    runs = tuple(sorted(value.runs, key=lambda run: run.label))
    exposed_sites: set[str] = set()
    for run in runs:
        groups = (run.protocol.train, run.protocol.selection, run.protocol.calibration)
        for index, group in enumerate(groups):
            for previous in groups[:index]:
                _require_disjoint(previous, group)
        prohibited = groups if run.protocol.purpose == "independent_test" else (run.protocol.train,)
        for group in prohibited:
            _require_disjoint(group, tuple(row.identity for row in truth))
        exposed_sites.update(identity.site_key for group in groups for identity in group)
    baseline = next(run.label for run in runs if run.role == "baseline")
    cohorts = {}
    for origin in COHORTS:
        rows = tuple(row for row in truth if row.cohort == origin)
        unseen = tuple(row for row in rows if row.identity.site_key not in exposed_sites)
        cohorts[origin] = ComparisonCohort(
            status="available" if rows else "missing",
            summary=_summary(rows, runs, baseline) if rows else None,
            common_unseen_sites=_summary(unseen, runs, baseline) if unseen else None,
            by_vendor={
                vendor: _summary(tuple(row for row in rows if row.vendor == vendor), runs, baseline)
                if any(row.vendor == vendor for row in rows)
                else None
                for vendor in ("cisco", "juniper")
            },
            by_role={
                role: _summary(
                    tuple(row for row in rows if (row.device_role or "<unrecorded>") == role),
                    runs,
                    baseline,
                )
                for role in sorted({row.device_role or "<unrecorded>" for row in rows})
            },
        )
    payload = _canonical_input(value)
    return DetectionComparisonReport(
        input_sha256=canonical_hash(payload),
        truth_sha256=canonical_hash(payload["truth"]),
        dataset_manifest_sha256=runs[0].protocol.dataset_manifest_sha256,
        purpose=runs[0].protocol.purpose,
        target_semantics=runs[0].protocol.target_semantics,
        latency_scope=runs[0].protocol.latency_scope,
        baseline=baseline,
        cohorts=cohorts,
        models={
            run["label"]: DetectorBinding(
                role=run["role"],
                model_version=run["protocol"]["model_version"],
                model_sha256=run["protocol"]["model_sha256"],
                tokenizer_sha256=run["protocol"]["tokenizer_sha256"],
                protocol_sha256=canonical_hash(run["protocol"]),
                threshold_policy_sha256=run["protocol"]["threshold_policy_sha256"],
                detection_threshold=run["protocol"]["detection_threshold"],
                score_kind=run["protocol"]["score_kind"],
                calibration_sha256=run["protocol"]["calibration_sha256"],
            )
            for run in payload["runs"]
        },
    )
