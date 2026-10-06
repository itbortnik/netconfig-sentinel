"""Separate-origin offline metrics with honest undefined/partial denominators."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Literal

import numpy as np
from sklearn.metrics import auc, average_precision_score, precision_recall_curve

from ml.evaluation.contracts import (
    COHORTS,
    EvaluationBatch,
    EvaluationCase,
    EvaluationProtocol,
    Frozen,
    Identity,
)


class ReliabilityBin(Frozen):
    lower: float
    upper: float
    count: int
    mean_probability: float | None
    positive_fraction: float | None


class CalibrationMetrics(Frozen):
    ece: float
    brier: float
    bins: tuple[ReliabilityBin, ...]


class BinaryMetrics(Frozen):
    label: str
    support: int
    negatives: int
    predicted_positive: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None
    f1: float | None
    average_precision: float | None
    pr_auc_trapezoidal: float | None
    ranking_unavailable_reason: str | None
    calibration: CalibrationMetrics | None


class PrecisionAtK(Frozen):
    requested_k: int
    precision: float | None
    expected_positive_count: float | None
    boundary_tie_size: int
    reason: str | None


class UnknownRanking(Frozen):
    annotated_cases: int
    scored_cases: int
    positive_cases: int
    average_precision: float | None
    pr_auc_trapezoidal: float | None
    precision_at_k: dict[int, PrecisionAtK]


class LocalizationMetrics(Frozen):
    annotated_cases: int
    evaluated_cases: int
    missing_annotation_cases: int
    excluded_deletion_cases: int
    eligible_lines: int
    scored_lines: int
    unscored_eligible_lines: int
    unscored_positive_lines: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None
    f1: float | None


class LatencyMetrics(Frozen):
    measured_cases: int
    missing_cases: int
    mean_seconds: float | None
    median_seconds: float | None
    p95_seconds: float | None
    max_seconds: float | None


class CoverageMetrics(Frozen):
    measured_cases: int
    missing_cases: int
    zero_significant_cases: int
    significant_lines: int
    recognized_lines: int
    micro_fraction: float | None
    macro_fraction: float | None


class SliceMetrics(Frozen):
    configurations: int
    unique_devices: int
    detection: BinaryMetrics
    categories: tuple[BinaryMetrics, ...]
    macro_f1: float | None
    macro_f1_defined_classes: int
    false_positives_per_device: float
    false_positives_per_configuration: float
    unknown_ranking: UnknownRanking
    localization: LocalizationMetrics
    latency: LatencyMetrics
    parser_coverage: CoverageMetrics


class CohortMetrics(Frozen):
    status: Literal["available", "missing"]
    summary: SliceMetrics | None
    unseen_sites: SliceMetrics | None
    by_vendor: dict[str, SliceMetrics | None]
    by_role: dict[str, SliceMetrics]


class EvaluationReport(Frozen):
    version: Literal["offline-metrics-0.1.0"] = "offline-metrics-0.1.0"
    input_sha256: str
    protocol_sha256: str
    model_version: str
    model_sha256: str
    tokenizer_sha256: str | None
    policy_version: str | None
    document_catalog_sha256: str | None
    calibration_sha256: str | None
    dataset_manifest_sha256: str
    threshold_policy_sha256: str
    detection_threshold: float
    category_thresholds: tuple[float, ...]
    score_kind: str
    target_semantics: str
    latency_scope: str
    partition: Literal["test", "validation"]
    independent_test: bool
    production_quality_proven: Literal[False] = False
    cohorts: dict[str, CohortMetrics]
    limitations: tuple[str, ...] = (
        "Caller-supplied source authorization, annotation and grouping hashes require review; "
        "this evaluator does not attest their semantic truth.",
        "No pooled metric combines synthetic, laboratory and confirmed-real examples.",
        "Selection/calibration reuse is diagnostic only. Scores never update online risk.",
        "Latency covers only the interval measured by the producer, not implied end-to-end time.",
        "Unknown ranking covers annotated scored cases; absent scores are reported separately.",
        "False positives per device count binary configuration alerts, not alert deduplication.",
    )


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _prf(tp: int, fp: int, fn: int) -> tuple[float | None, float | None, float | None]:
    return _ratio(tp, tp + fp), _ratio(tp, tp + fn), _ratio(2 * tp, 2 * tp + fp + fn)


def ranking_metrics(truth: Sequence[bool], scores: Sequence[float]) -> tuple[float | None, ...]:
    if not truth or not 0 < sum(truth) < len(truth):
        return None, None
    precision, recall, _ = precision_recall_curve(truth, scores)
    return float(average_precision_score(truth, scores)), float(auc(recall, precision))


def calibration_metrics(
    truth: Sequence[bool],
    scores: Sequence[float],
    bins: int,
) -> CalibrationMetrics:
    """Equal-width binary reliability, including empty bins and p=1 in the last bin."""
    counts, probabilities, positives = [0] * bins, [0.0] * bins, [0] * bins
    for label, score in zip(truth, scores, strict=True):
        index = min(int(score * bins), bins - 1)
        counts[index] += 1
        probabilities[index] += score
        positives[index] += label
    groups = []
    error = 0.0
    for index in range(bins):
        count = counts[index]
        probability = probabilities[index] / count if count else None
        observed = positives[index] / count if count else None
        if probability is not None and observed is not None:
            error += count * abs(probability - observed) / len(truth)
        groups.append(
            ReliabilityBin(
                lower=index / bins,
                upper=(index + 1) / bins,
                count=count,
                mean_probability=probability,
                positive_fraction=observed,
            )
        )
    return CalibrationMetrics(
        ece=error,
        brier=sum((score - label) ** 2 for label, score in zip(truth, scores, strict=True))
        / len(truth),
        bins=tuple(groups),
    )


def binary_metrics(
    label: str,
    truth: Sequence[bool],
    scores: Sequence[float],
    threshold: float,
    protocol: EvaluationProtocol,
) -> BinaryMetrics:
    predicted = [score > threshold for score in scores]
    tp = sum(actual and selected for actual, selected in zip(truth, predicted, strict=True))
    fp = sum(not actual and selected for actual, selected in zip(truth, predicted, strict=True))
    fn = sum(actual and not selected for actual, selected in zip(truth, predicted, strict=True))
    precision, recall, f1 = _prf(tp, fp, fn)
    ap, area = ranking_metrics(truth, scores)
    return BinaryMetrics(
        label=label,
        support=sum(truth),
        negatives=len(truth) - sum(truth),
        predicted_positive=sum(predicted),
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=len(truth) - tp - fp - fn,
        precision=precision,
        recall=recall,
        f1=f1,
        average_precision=ap,
        pr_auc_trapezoidal=area,
        ranking_unavailable_reason=None
        if ap is not None
        else "requires_positive_and_negative_cases",
        calibration=calibration_metrics(truth, scores, protocol.reliability_bins)
        if protocol.score_kind == "probability"
        else None,
    )


def _unknown(cases: tuple[EvaluationCase, ...], ks: tuple[int, ...]) -> UnknownRanking:
    annotated = [case for case in cases if case.unknown_truth is not None]
    scored = [case for case in annotated if case.unknown_score is not None]
    scores = [float(case.unknown_score) for case in scored if case.unknown_score is not None]
    truth = [bool(case.unknown_truth) for case in scored]
    ap, area = ranking_metrics(truth, scores)
    pairs = sorted(zip(scores, truth, strict=True), reverse=True)
    values = {}
    for k in ks:
        if len(pairs) < k:
            values[k] = PrecisionAtK(
                requested_k=k,
                precision=None,
                expected_positive_count=None,
                boundary_tie_size=0,
                reason="insufficient_scored_cases",
            )
            continue
        boundary = pairs[k - 1][0]
        above = [label for score, label in pairs if score > boundary]
        tied = [label for score, label in pairs if score == boundary]
        expected = sum(above) + (k - len(above)) * sum(tied) / len(tied)
        values[k] = PrecisionAtK(
            requested_k=k,
            precision=expected / k,
            expected_positive_count=expected,
            boundary_tie_size=len(tied),
            reason=None,
        )
    return UnknownRanking(
        annotated_cases=len(annotated),
        scored_cases=len(scored),
        positive_cases=sum(truth),
        average_precision=ap,
        pr_auc_trapezoidal=area,
        precision_at_k=values,
    )


def _localization(cases: tuple[EvaluationCase, ...]) -> LocalizationMetrics:
    annotations = [case.lines for case in cases if case.lines is not None]
    included = [lines for lines in annotations if not lines.deletion_only]
    tp = fp = fn = tn = eligible = scored_count = unscored_positive = 0
    for lines in included:
        truth, scored, predicted = map(
            set, (lines.positive_lines, lines.scored_lines, lines.predicted_lines)
        )
        tp += len(truth & predicted)
        fp += len(predicted - truth)
        fn += len(truth - predicted)  # Unscored positives do not quietly disappear.
        tn += len(scored - truth - predicted)
        unscored_positive += len(truth - scored)
        eligible += lines.total_lines - len(lines.ignored_lines)
        scored_count += len(scored)
    precision, recall, f1 = _prf(tp, fp, fn)
    return LocalizationMetrics(
        annotated_cases=len(annotations),
        evaluated_cases=len(included),
        missing_annotation_cases=len(cases) - len(annotations),
        excluded_deletion_cases=len(annotations) - len(included),
        eligible_lines=eligible,
        scored_lines=scored_count,
        unscored_eligible_lines=eligible - scored_count,
        unscored_positive_lines=unscored_positive,
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=tn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def _latency(cases: tuple[EvaluationCase, ...]) -> LatencyMetrics:
    values = [case.analysis_seconds for case in cases if case.analysis_seconds is not None]
    return LatencyMetrics(
        measured_cases=len(values),
        missing_cases=len(cases) - len(values),
        mean_seconds=float(np.mean(values)) if values else None,
        median_seconds=float(np.median(values)) if values else None,
        p95_seconds=float(np.quantile(values, 0.95, method="linear")) if values else None,
        max_seconds=max(values) if values else None,
    )


def _coverage(cases: tuple[EvaluationCase, ...]) -> CoverageMetrics:
    values = [case.parser_coverage for case in cases if case.parser_coverage is not None]
    fractions = [
        value.recognized_lines / value.significant_lines
        for value in values
        if value.significant_lines
    ]
    total = sum(value.significant_lines for value in values)
    recognized = sum(value.recognized_lines for value in values)
    return CoverageMetrics(
        measured_cases=len(values),
        missing_cases=len(cases) - len(values),
        zero_significant_cases=len(values) - len(fractions),
        significant_lines=total,
        recognized_lines=recognized,
        micro_fraction=_ratio(recognized, total),
        macro_fraction=sum(fractions) / len(fractions) if fractions else None,
    )


def _summary(cases: tuple[EvaluationCase, ...], protocol: EvaluationProtocol) -> SliceMetrics:
    detection = binary_metrics(
        "anomaly",
        [case.anomaly_truth for case in cases],
        [case.detection_score for case in cases],
        protocol.detection_threshold,
        protocol,
    )
    categories = tuple(
        binary_metrics(
            label,
            [label in case.category_truth for case in cases],
            [case.category_scores[index] for case in cases],
            protocol.category_thresholds[index],
            protocol,
        )
        for index, label in enumerate(protocol.classes)
    )
    f1s = [metric.f1 for metric in categories if metric.f1 is not None]
    devices = len({case.identity.device_key for case in cases})
    return SliceMetrics(
        configurations=len(cases),
        unique_devices=devices,
        detection=detection,
        categories=categories,
        macro_f1=sum(f1s) / len(f1s) if f1s else None,
        macro_f1_defined_classes=len(f1s),
        false_positives_per_device=detection.false_positive / devices,
        false_positives_per_configuration=detection.false_positive / len(cases),
        unknown_ranking=_unknown(cases, protocol.precision_at_k),
        localization=_localization(cases),
        latency=_latency(cases),
        parser_coverage=_coverage(cases),
    )


def _exposures(protocol: EvaluationProtocol, cases: tuple[EvaluationCase, ...]) -> set[str]:
    groups = (protocol.train, protocol.selection, protocol.calibration)
    # Consistent disjoint entities are required across training/selection/calibration.
    for index, group in enumerate(groups):
        for previous in groups[:index]:
            _require_disjoint(previous, group)
    prohibited = groups if protocol.purpose == "independent_test" else (protocol.train,)
    for group in prohibited:
        _require_disjoint(group, tuple(case.identity for case in cases))
    return {identity.site_key for group in groups for identity in group}


def _require_disjoint(first: tuple[Identity, ...], second: tuple[Identity, ...]) -> None:
    for field in Identity.model_fields:
        if {getattr(item, field) for item in first} & {getattr(item, field) for item in second}:
            raise ValueError("evaluation exposure crosses partition boundaries")


def evaluate(batch: EvaluationBatch) -> EvaluationReport:
    """Revalidate copied models, enforce exposure gates, never pool origin cohorts."""
    batch = EvaluationBatch.model_validate(batch.model_dump())
    protocol = batch.protocol
    cases = tuple(sorted(batch.cases, key=lambda case: case.case_id))
    exposed_sites = _exposures(protocol, cases)
    cohorts = {}
    for origin in COHORTS:
        rows = tuple(case for case in cases if case.cohort == origin)
        unseen = tuple(case for case in rows if case.identity.site_key not in exposed_sites)
        cohorts[origin] = CohortMetrics(
            status="available" if rows else "missing",
            summary=_summary(rows, protocol) if rows else None,
            unseen_sites=_summary(unseen, protocol) if unseen else None,
            by_vendor={
                vendor: _summary(tuple(case for case in rows if case.vendor == vendor), protocol)
                if any(case.vendor == vendor for case in rows)
                else None
                for vendor in ("cisco", "juniper")
            },
            by_role={
                role: _summary(
                    tuple(case for case in rows if (case.device_role or "unrecorded") == role),
                    protocol,
                )
                for role in sorted({case.device_role or "unrecorded" for case in rows})
            },
        )
    # Exposure order is irrelevant; predictions are bound, but no grouping IDs are output.
    protocol_data = protocol.model_dump(mode="json")
    for group in ("train", "selection", "calibration"):
        protocol_data[group] = sorted(protocol_data[group], key=canonical_hash)
    return EvaluationReport(
        input_sha256=canonical_hash(
            {"protocol": protocol_data, "cases": [case.model_dump(mode="json") for case in cases]}
        ),
        protocol_sha256=canonical_hash(protocol_data),
        model_version=protocol.model_version,
        model_sha256=protocol.model_sha256,
        tokenizer_sha256=protocol.tokenizer_sha256,
        policy_version=protocol.policy_version,
        document_catalog_sha256=protocol.document_catalog_sha256,
        calibration_sha256=protocol.calibration_sha256,
        dataset_manifest_sha256=protocol.dataset_manifest_sha256,
        threshold_policy_sha256=protocol.threshold_policy_sha256,
        detection_threshold=protocol.detection_threshold,
        category_thresholds=protocol.category_thresholds,
        score_kind=protocol.score_kind,
        target_semantics=protocol.target_semantics,
        latency_scope=protocol.latency_scope,
        partition="test" if protocol.purpose == "independent_test" else "validation",
        independent_test=protocol.purpose == "independent_test",
        cohorts=cohorts,
    )
