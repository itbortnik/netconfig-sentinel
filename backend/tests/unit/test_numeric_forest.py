"""Numeric-only persistence must match sklearn, reject malformed graphs and never refit."""

from copy import deepcopy
from uuid import uuid4

import numpy as np
import pytest
from app.detection.statistical.artifact import ForestArtifact, export_forest
from app.detection.statistical.features import extract_structured_features
from app.detection.statistical.isolation_forest import (
    evaluate_isolation_forest,
    fit_isolation_forest,
)
from app.explanation.local import explain_finding
from app.parsers import parse_configuration


def configuration(index: int, *, vlans: int | None = None):
    lines = [f"hostname forest-{index}", "aaa new-model", "ip ssh version 2"]
    for vlan in range(vlans if vlans is not None else index % 7 + 1):
        lines.extend([f"vlan {10 + vlan}", f" name VLAN-{vlan}", "!"])
    config = parse_configuration("\n".join(lines) + "\n", filename="forest.cfg")
    config.device.role = "edge"
    config.device.site_class = "branch"
    config.device.service_profile = "control"
    return config


@pytest.mark.parametrize("count", [2, 8, 16, 100, 256, 300])
def test_numeric_roundtrip_matches_sklearn_scores_and_thresholds(count, monkeypatch) -> None:
    configs = [configuration(index) for index in range(count)]
    fitted = fit_isolation_forest(configs, minimum_samples=2, estimator_count=32)
    artifact = export_forest(fitted)
    loaded = ForestArtifact.model_validate_json(artifact.model_dump_json())
    rows = [extract_structured_features(item).as_row() for item in configs]
    rows.extend(np.random.default_rng(42).uniform(0, 40, size=(50, 33)).tolist())
    # Include actual split thresholds and adjacent representable float32 values.
    for tree in loaded.trees[:2]:
        for feature, threshold in zip(tree.features, tree.thresholds, strict=True):
            if feature >= 0:
                for value in (threshold, np.nextafter(np.float32(threshold), np.float32(np.inf))):
                    row = rows[0].copy()
                    row[feature] = float(value)
                    rows.append(row)
    assert loaded.score_samples(rows) == pytest.approx(
        fitted.estimator.score_samples(rows), abs=1e-14
    )
    assert loaded.decision_function(rows) == pytest.approx(
        fitted.estimator.decision_function(rows),
        abs=1e-14,
    )
    assert loaded.predict(rows) == list(fitted.estimator.predict(rows))
    assert artifact.fingerprint() == loaded.fingerprint()
    monkeypatch.setattr("sklearn.ensemble.IsolationForest.fit", lambda *args: pytest.fail("refit"))
    assert loaded.predict(rows) == artifact.predict(rows)


def test_identical_vectors_and_outlier_explanation() -> None:
    configs = [configuration(index, vlans=2) for index in range(8)]
    fitted = fit_isolation_forest(configs, estimator_count=32)
    loaded = export_forest(fitted)
    rows = [extract_structured_features(item).as_row() for item in configs]
    assert loaded.score_samples(rows) == pytest.approx(fitted.estimator.score_samples(rows))
    assert loaded.predict(rows) == [1] * 8
    # A varied population makes a held-out extreme configuration an outlier.
    model = export_forest(fit_isolation_forest([configuration(i) for i in range(16)]))
    target = configuration(999, vlans=30)
    finding = evaluate_isolation_forest(target, model.fitted(), device_id=uuid4())[0]
    explanation = explain_finding(finding, target, statistical_model=model.fitted())
    assert "not causal" in explanation.technical_explanation
    with pytest.raises(ValueError, match="require"):
        explain_finding(finding, target)
    modified = finding.model_copy(update={"confidence": 0.9})
    with pytest.raises(ValueError, match="stale"):
        explain_finding(modified, target, statistical_model=model.fitted())


@pytest.mark.parametrize(
    "mutation",
    [
        "cycle",
        "missing_child",
        "shared_child",
        "feature",
        "nan",
        "population",
        "disconnected",
        "too_many_nodes",
        "offset",
        "format",
        "schema",
        "count",
        "executable",
    ],
)
def test_malformed_artifacts_are_rejected(mutation: str) -> None:
    data = deepcopy(
        export_forest(fit_isolation_forest([configuration(i) for i in range(8)])).model_dump(
            mode="json"
        )
    )
    tree = data["trees"][0]
    if mutation == "cycle":
        tree["left"][0] = 0
    elif mutation == "missing_child":
        tree["left"][0] = 1000
    elif mutation == "shared_child":
        tree["right"][0] = tree["left"][0]
    elif mutation == "feature":
        tree["features"][0] = 33
    elif mutation == "nan":
        tree["thresholds"][0] = float("nan")
    elif mutation == "population":
        tree["samples"][0] = 1
    elif mutation == "disconnected":
        for key, value in {
            "left": -1,
            "right": -1,
            "features": -2,
            "thresholds": -2,
            "samples": 1,
        }.items():
            tree[key].append(value)
    elif mutation == "too_many_nodes":
        tree["left"] = [-1] * 512
    elif mutation == "offset":
        data["offset"] = float("inf")
    elif mutation == "format":
        data["format"] = "pickle"
    elif mutation == "schema":
        data["metadata"]["feature_schema_version"] = "future-unknown"
    elif mutation == "count":
        data["metadata"]["estimator_count"] += 1
    else:
        data["__reduce__"] = ["os.system", "never-execute"]
    with pytest.raises(ValueError):
        ForestArtifact.model_validate(data)


def test_scorer_rejects_nonfinite_and_wrong_dimensions() -> None:
    model = export_forest(fit_isolation_forest([configuration(i) for i in range(8)]))
    for row in ([0.0], [float("nan")] * 33, [float("inf")] * 33):
        with pytest.raises(ValueError):
            model.score_samples([row])
