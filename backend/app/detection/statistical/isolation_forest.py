"""Reproducible Isolation Forest detector for canonical configurations."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from statistics import median
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sklearn import __version__ as sklearn_version
from sklearn.ensemble import IsolationForest

from app.detection.baseline import PeerGroupKey
from app.detection.statistical.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    StructuredFeatureVector,
    extract_structured_features,
)
from app.domain import CanonicalConfig, Evidence, Finding, Severity, SourceLocation

ISOLATION_FOREST_NAMESPACE = UUID("d28f81a6-b6f6-4459-9c25-a987a6cf4cc6")
ISOLATION_FOREST_MODEL_VERSION = "isolation-forest-0.1.0"


class IsolationForestMetadata(BaseModel):
    """Serializable training metadata required to interpret detector output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_version: str = ISOLATION_FOREST_MODEL_VERSION
    library_version: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    feature_names: tuple[str, ...] = FEATURE_NAMES
    group: PeerGroupKey
    sample_count: int = Field(ge=2)
    contamination: float = Field(gt=0.0, le=0.5)
    random_state: int
    estimator_count: int = Field(ge=1)
    training_score_min: float
    training_score_max: float
    feature_medians: tuple[float, ...]
    feature_scales: tuple[float, ...]

    @model_validator(mode="after")
    def dimensions_and_range_are_valid(self) -> IsolationForestMetadata:
        expected_length = len(self.feature_names)
        if self.feature_names != FEATURE_NAMES:
            raise ValueError("metadata feature names do not match the supported schema")
        if len(self.feature_medians) != expected_length:
            raise ValueError("feature medians do not match the feature schema")
        if len(self.feature_scales) != expected_length:
            raise ValueError("feature scales do not match the feature schema")
        if any(scale <= 0.0 for scale in self.feature_scales):
            raise ValueError("feature scales must be positive")
        if self.training_score_min > self.training_score_max:
            raise ValueError("training score range is invalid")
        return self


@dataclass(frozen=True)
class FittedIsolationForest:
    """In-memory estimator paired with its versioned, auditable metadata."""

    metadata: IsolationForestMetadata
    estimator: IsolationForest


def fit_isolation_forest(
    configs: Sequence[CanonicalConfig],
    *,
    minimum_samples: int = 8,
    contamination: float = 0.1,
    random_state: int = 42,
    estimator_count: int = 200,
) -> FittedIsolationForest:
    """Fit a reproducible model for one explicit peer group."""

    if minimum_samples < 2:
        raise ValueError("minimum_samples must be at least 2")
    if len(configs) < minimum_samples:
        raise ValueError(
            f"Isolation Forest requires at least {minimum_samples} configurations"
        )
    if not 0.0 < contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and at most 0.5")
    if estimator_count < 1:
        raise ValueError("estimator_count must be positive")

    group = PeerGroupKey.from_config(configs[0])
    for config in configs[1:]:
        if PeerGroupKey.from_config(config) != group:
            raise ValueError("all training configurations must belong to one peer group")

    vectors = [extract_structured_features(config) for config in configs]
    matrix = [vector.as_row() for vector in vectors]
    estimator = IsolationForest(
        n_estimators=estimator_count,
        contamination=contamination,
        random_state=random_state,
        n_jobs=1,
    )
    estimator.fit(matrix)
    training_scores = [-float(score) for score in estimator.score_samples(matrix)]
    columns = list(zip(*(vector.values for vector in vectors), strict=True))
    feature_medians = tuple(float(median(column)) for column in columns)
    feature_scales = tuple(_robust_scale(column, center) for column, center in zip(
        columns, feature_medians, strict=True
    ))
    metadata = IsolationForestMetadata(
        library_version=sklearn_version,
        group=group,
        sample_count=len(configs),
        contamination=contamination,
        random_state=random_state,
        estimator_count=estimator_count,
        training_score_min=min(training_scores),
        training_score_max=max(training_scores),
        feature_medians=feature_medians,
        feature_scales=feature_scales,
    )
    return FittedIsolationForest(metadata=metadata, estimator=estimator)


def evaluate_isolation_forest(
    config: CanonicalConfig,
    model: FittedIsolationForest,
    *,
    device_id: UUID,
) -> list[Finding]:
    """Return one statistical finding when the fitted forest flags an outlier."""

    if PeerGroupKey.from_config(config) != model.metadata.group:
        raise ValueError("configuration does not belong to the model peer group")
    vector = extract_structured_features(config)
    row = [vector.as_row()]
    prediction = int(model.estimator.predict(row)[0])
    if prediction != -1:
        return []

    raw_score = -float(model.estimator.score_samples(row)[0])
    decision = float(model.estimator.decision_function(row)[0])
    deviations = _top_deviations(vector, model.metadata)
    locations = _deviation_locations(vector, deviations)
    affected_lines = sorted(
        {line for location in locations for line in location.source_lines}
    )
    evidence = [
        Evidence(
            kind="statistical_feature_deviation",
            message=(
                f"{item['feature']} differs from the training median "
                f"by {item['scaled_deviation']:.3f} robust scale units."
            ),
            source_location=_first_feature_location(vector, item),
        )
        for item in deviations
    ]
    if not evidence:
        evidence.append(
            Evidence(
                kind="statistical_outlier",
                message="The complete structured vector was classified as an outlier.",
            )
        )
    category = "statistical.configuration_outlier"
    return [
        Finding(
            finding_id=_finding_id(
                device_id, model.metadata.group, category, affected_lines
            ),
            device_id=device_id,
            detector="isolation_forest",
            category=category,
            title="Configuration is a structured-feature outlier",
            severity=Severity.MEDIUM,
            confidence=min(
                config.parser_confidence,
                model.metadata.sample_count / 50.0,
                1.0,
            ),
            anomaly_score=_normalize_score(raw_score, model.metadata),
            affected_lines=affected_lines,
            evidence=evidence,
            observed={
                "raw_anomaly_score": raw_score,
                "decision_function": decision,
                "top_feature_deviations": deviations,
            },
            expected={
                "decision_function": ">= 0",
                "training_score_min": model.metadata.training_score_min,
                "training_score_max": model.metadata.training_score_max,
                "training_sample_count": model.metadata.sample_count,
            },
            remediation=(
                "Review the highlighted features against policy, peer baseline, and "
                "the intended change record before proposing remediation."
            ),
            references=("docs/statistical-baseline.md#finding-interpretation",),
            limitations=[
                "Feature deviations are diagnostic context, not per-feature tree "
                "attributions or causal explanations.",
                "The detector is a control model and must be evaluated separately from "
                "policy and future Transformer results.",
            ],
            model_version=model.metadata.model_version,
        )
    ]


def _robust_scale(values: tuple[float, ...], center: float) -> float:
    absolute_deviations = [abs(value - center) for value in values]
    mad = float(median(absolute_deviations))
    return max(mad, 1.0)


def _top_deviations(
    vector: StructuredFeatureVector,
    metadata: IsolationForestMetadata,
    *,
    limit: int = 3,
) -> list[dict[str, float | str]]:
    ranked = sorted(
        (
            (
                abs(value - center) / scale,
                name,
                value,
                center,
            )
            for name, value, center, scale in zip(
                vector.names,
                vector.values,
                metadata.feature_medians,
                metadata.feature_scales,
                strict=True,
            )
        ),
        key=lambda item: (-item[0], item[1]),
    )
    return [
        {
            "feature": name,
            "observed": value,
            "training_median": center,
            "scaled_deviation": deviation,
        }
        for deviation, name, value, center in ranked[:limit]
        if deviation > 0.0
    ]


def _deviation_locations(
    vector: StructuredFeatureVector,
    deviations: list[dict[str, float | str]],
) -> tuple[SourceLocation, ...]:
    candidates: list[SourceLocation] = []
    for deviation in deviations:
        name = deviation["feature"]
        if isinstance(name, str):
            candidates.extend(vector.locations.get(name, ()))
    locations: list[SourceLocation] = []
    seen: set[tuple[tuple[int, ...], str]] = set()
    for location in sorted(candidates, key=lambda item: item.source_lines[0]):
        key = (tuple(location.source_lines), location.raw_text_hash)
        if key not in seen:
            locations.append(location)
            seen.add(key)
    return tuple(locations)


def _first_feature_location(
    vector: StructuredFeatureVector,
    deviation: dict[str, float | str],
) -> SourceLocation | None:
    name = deviation["feature"]
    if not isinstance(name, str):
        return None
    locations = vector.locations.get(name, ())
    return locations[0] if locations else None


def _normalize_score(score: float, metadata: IsolationForestMetadata) -> float:
    width = metadata.training_score_max - metadata.training_score_min
    if width <= 0.0:
        return 1.0 if score > metadata.training_score_max else 0.5
    return min(1.0, max(0.0, (score - metadata.training_score_min) / width))


def _finding_id(
    device_id: UUID,
    group: PeerGroupKey,
    category: str,
    affected_lines: list[int],
) -> UUID:
    group_key = "|".join(
        (
            group.vendor.value,
            group.platform,
            group.device_role,
            group.site_class,
            group.service_profile,
        )
    )
    line_key = ",".join(str(line) for line in affected_lines)
    return uuid5(
        ISOLATION_FOREST_NAMESPACE,
        f"{device_id}:{group_key}:{category}:{line_key}",
    )
