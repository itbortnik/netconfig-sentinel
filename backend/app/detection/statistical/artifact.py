"""Bounded numeric JSON forest. Loading never imports or executes artifact objects."""

from __future__ import annotations

import json
from collections.abc import Sequence
from hashlib import sha256
from typing import Literal
from uuid import UUID

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sklearn.ensemble import IsolationForest

from app.detection.statistical.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from app.detection.statistical.isolation_forest import (
    ISOLATION_FOREST_MODEL_VERSION,
    FittedIsolationForest,
    IsolationForestMetadata,
)


def average_path_length(samples: int) -> float:
    """The approximation used by scikit-learn, including singleton/two-sample leaves."""
    if samples <= 1:
        return 0.0
    if samples == 2:
        return 1.0
    return float(2 * (np.log(samples - 1.0) + np.euler_gamma) - 2 * (samples - 1) / samples)


class NumericTree(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    left: tuple[int, ...] = Field(min_length=1, max_length=511)
    right: tuple[int, ...] = Field(min_length=1, max_length=511)
    features: tuple[int, ...] = Field(min_length=1, max_length=511)
    thresholds: tuple[float, ...] = Field(min_length=1, max_length=511)
    samples: tuple[int, ...] = Field(min_length=1, max_length=511)

    @model_validator(mode="after")
    def valid_tree(self) -> NumericTree:
        size = len(self.left)
        if any(
            len(values) != size
            for values in (
                self.right,
                self.features,
                self.thresholds,
                self.samples,
            )
        ):
            raise ValueError("tree dimensions differ")
        parents = [0] * size
        depths = [0] * size
        for node, (left, right, feature, count) in enumerate(
            zip(
                self.left,
                self.right,
                self.features,
                self.samples,
                strict=True,
            )
        ):
            if not 1 <= count <= 256 or depths[node] > 8:
                raise ValueError("invalid tree depth or sample count")
            if left == right == -1:
                if feature != -2:
                    raise ValueError("invalid leaf feature")
                continue
            if not (node < left < size and node < right < size and left != right):
                raise ValueError("invalid tree edges")
            if not 0 <= feature < len(FEATURE_NAMES):
                raise ValueError("invalid split feature")
            if self.samples[left] + self.samples[right] != count:
                raise ValueError("invalid split population")
            for child in (left, right):
                parents[child] += 1
                depths[child] = depths[node] + 1
        if parents[0] != 0 or any(count != 1 for count in parents[1:]):
            raise ValueError("tree must be connected with unique parents")
        return self

    def path_length(self, row: Sequence[float]) -> float:
        node, depth = 0, 0
        while self.left[node] != -1:
            feature = self.features[node]
            node = self.left[node] if row[feature] <= self.thresholds[node] else self.right[node]
            depth += 1
        # Preserve sklearn's operation order at the exact zero decision boundary.
        return (depth + 1) + average_path_length(self.samples[node]) - 1


class ForestArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    format: Literal["numeric-isolation-forest-0.1.0"] = "numeric-isolation-forest-0.1.0"
    metadata: IsolationForestMetadata
    trees: tuple[NumericTree, ...] = Field(min_length=1, max_length=200)
    max_samples: int = Field(ge=2, le=256)
    offset: float = Field(ge=-1, le=0)

    @model_validator(mode="after")
    def supported_forest(self) -> ForestArtifact:
        if (
            self.metadata.model_version != ISOLATION_FOREST_MODEL_VERSION
            or self.metadata.feature_schema_version != FEATURE_SCHEMA_VERSION
            or len(self.trees) != self.metadata.estimator_count
            or self.max_samples != min(256, self.metadata.sample_count)
            or any(tree.samples[0] != self.max_samples for tree in self.trees)
        ):
            raise ValueError("unsupported forest metadata")
        return self

    def fingerprint(self) -> str:
        contents = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return sha256(contents.encode("utf-8")).hexdigest()

    def score_samples(self, rows: Sequence[Sequence[float]]) -> list[float]:
        denominator = len(self.trees) * average_path_length(self.max_samples)
        depths = []
        for row in rows:
            if len(row) != len(FEATURE_NAMES):
                raise ValueError("incompatible feature dimensions")
            # sklearn tree evaluation casts input to float32 before threshold comparison.
            numeric = np.asarray(row, dtype=np.float32)
            if not np.isfinite(numeric).all():
                raise ValueError("features must be finite")
            depth = 0.0
            numeric_row = numeric.tolist()
            # Python 3.12+ sum() uses compensated summation; sklearn accumulates sequentially.
            for tree in self.trees:
                depth += tree.path_length(numeric_row)
            depths.append(depth)
        # Vectorized power follows sklearn's numeric path, including exact zero decisions.
        values = -(2 ** (-np.asarray(depths, dtype=np.float64) / denominator))
        return list(map(float, values))

    def decision_function(self, rows: Sequence[Sequence[float]]) -> list[float]:
        return [score - self.offset for score in self.score_samples(rows)]

    def predict(self, rows: Sequence[Sequence[float]]) -> list[int]:
        return [-1 if decision < 0 else 1 for decision in self.decision_function(rows)]

    def fitted(self, *, registry_id: UUID | None = None) -> FittedIsolationForest:
        return FittedIsolationForest(
            metadata=self.metadata,
            estimator=self,
            registry_id=registry_id,
            artifact_sha256=self.fingerprint() if registry_id is not None else None,
        )


def export_forest(model: FittedIsolationForest) -> ForestArtifact:
    estimator = model.estimator
    if not isinstance(estimator, IsolationForest) or (
        estimator.max_features != 1.0 or estimator.bootstrap
    ):
        raise ValueError("only standard locally fitted forests can be exported")
    if any(
        list(features) != list(range(len(FEATURE_NAMES)))
        for features in estimator.estimators_features_
    ):
        raise ValueError("feature-subset forests are not supported")
    trees = tuple(
        NumericTree(
            left=tree.tree_.children_left.tolist(),
            right=tree.tree_.children_right.tolist(),
            features=tree.tree_.feature.tolist(),
            thresholds=tree.tree_.threshold.tolist(),
            samples=tree.tree_.n_node_samples.tolist(),
        )
        for tree in estimator.estimators_
    )
    return ForestArtifact(
        metadata=model.metadata,
        trees=trees,
        max_samples=estimator.max_samples_,
        offset=float(estimator.offset_),
    )
