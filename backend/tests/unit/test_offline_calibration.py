"""Independent calibration fit, binding and validation-only threshold selection."""

import pytest
from test_offline_evaluation import batch, case, identity

from ml.evaluation.calibration import (
    CalibrationPolicy,
    apply_calibration,
    artifact_identity,
    fit_calibration,
)
from ml.evaluation.metrics import evaluate


def calibration_rows():
    return [
        case(
            str(i),
            anomaly_truth=(i % 2 == 0),
            category_truth=("routing", "management") if i % 2 == 0 else (),
            detection_score=0.6 if i % 2 == 0 else 0.7,
            category_scores=(0.6, 0.6) if i % 2 == 0 else (0.7, 0.7),
        )
        for i in range(24)
    ]


def test_temperature_and_thresholds_fit_only_calibration_and_apply_unchanged_model():
    source = batch(calibration_rows(), purpose="validation_diagnostic")
    artifact = fit_calibration(source)
    assert artifact.production_quality_proven is False
    assert artifact.calibration_input_sha256 == evaluate(source).input_sha256
    assert all(channel.calibrated_nll <= channel.original_nll for channel in artifact.channels)
    assert all(channel.temperature == 10 for channel in artifact.channels)
    assert artifact == fit_calibration(
        batch(list(reversed(calibration_rows())), purpose="validation_diagnostic")
    )
    test = batch(
        [
            case(
                "held-out",
                anomaly_truth=True,
                category_truth=("routing",),
                detection_score=0.9,
                category_scores=(0.9, 0.1),
            )
        ]
    )
    calibrated = apply_calibration(test, artifact)
    assert calibrated.protocol.model_sha256 == test.protocol.model_sha256
    assert calibrated.protocol.calibration_sha256 == artifact_identity(artifact)
    assert calibrated.cases[0].anomaly_truth == test.cases[0].anomaly_truth
    assert calibrated.cases[0].detection_score < test.cases[0].detection_score
    assert evaluate(calibrated).independent_test is True
    assert apply_calibration(test, artifact) == calibrated


@pytest.mark.parametrize(
    "updates",
    [
        {"score_kind": "ranking"},
        {"purpose": "independent_test"},
        {"selection": (identity("0"),)},
    ],
)
def test_fit_rejects_test_scores_ranking_or_selection_reuse(updates):
    values = {"purpose": "validation_diagnostic", **updates}
    with pytest.raises(ValueError):
        fit_calibration(batch(calibration_rows(), **values))


def test_fit_requires_enough_positive_and_negative_annotations_for_every_channel():
    with pytest.raises(ValueError, match="support"):
        fit_calibration(batch([case("a")], purpose="validation_diagnostic"))
    with pytest.raises(ValueError, match="support"):
        fit_calibration(
            batch(
                [
                    case(
                        str(i),
                        anomaly_truth=bool(i % 2),
                        category_truth=("routing",) if i % 2 else (),
                    )
                    for i in range(24)
                ],
                purpose="validation_diagnostic",
            )
        )


def test_apply_rejects_any_model_corpus_or_exposure_change_and_calibration_overlap():
    artifact = fit_calibration(batch(calibration_rows(), purpose="validation_diagnostic"))
    for changed in (
        batch([case("held-out")], model_sha256="0" * 64),
        batch([case("held-out")], dataset_manifest_sha256="0" * 64),
        batch([case("held-out")], classes=("a", "b")),
        batch([case("held-out")], train=(identity("different-train"),)),
        batch([case("0")]),
    ):
        with pytest.raises(ValueError):
            apply_calibration(changed, artifact)
    good = apply_calibration(batch([case("held-out")]), artifact)
    with pytest.raises(ValueError, match="already"):
        apply_calibration(good, artifact)


def test_diagnostic_application_cannot_hide_reuse_as_unseen_or_independent():
    artifact = fit_calibration(batch(calibration_rows(), purpose="validation_diagnostic"))
    report = evaluate(
        apply_calibration(batch([case("0")], purpose="validation_diagnostic"), artifact)
    )
    assert report.independent_test is False
    assert report.cohorts["synthetic"].unseen_sites is None


def test_calibration_grid_is_bounded_and_includes_identity():
    for values in (
        {"temperatures": (2, 3)},
        {"temperatures": (1, float("nan"))},
        {"thresholds": (0.5, 0.2)},
        {"minimum_class_support": 0},
    ):
        with pytest.raises(ValueError):
            CalibrationPolicy(**values)


def test_zero_one_probabilities_are_finite_and_weak_artifacts_revalidate():
    source = batch(
        [
            case(
                str(i),
                anomaly_truth=(i % 2 == 0),
                category_truth=("routing", "management") if i % 2 == 0 else (),
                detection_score=1 if i % 2 == 0 else 0,
                category_scores=(1, 1) if i % 2 == 0 else (0, 0),
            )
            for i in range(24)
        ],
        purpose="validation_diagnostic",
    )
    artifact = fit_calibration(source)
    assert all(channel.temperature == 1 for channel in artifact.channels)
    broken = artifact.model_copy(update={"channels": ()})
    with pytest.raises(ValueError):
        apply_calibration(batch([case("held-out")]), broken)
