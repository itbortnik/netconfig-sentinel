"""Authored score tables exercise calibration math, never model or network quality."""

import numpy as np
import pytest

from ml.evaluation.calibration import CalibrationPolicy
from ml.evaluation.contracts import Identity
from ml.evaluation.metrics import canonical_hash
from ml.evaluation.severity import (
    _scaled,
    apply_severity_calibration,
    evaluate_severity,
    fit_severity_calibration,
    severity_artifact_identity,
    severity_batch_identity,
)
from ml.evaluation.severity_contracts import (
    SEVERITY_CLASSES,
    SeverityEvaluationBatch,
    SeverityEvaluationCase,
    SeverityEvaluationProtocol,
)


def identity(partition, index):
    return Identity(
        **{
            name: canonical_hash((partition, index if name == "source_sha256" else "group", name))
            for name in Identity.model_fields
        }
    )


def numeric_cases(partition, per_class=3):
    rows = []
    for category, label in enumerate(SEVERITY_CLASSES):
        for sample in range(per_class):
            index = category * per_class + sample
            chosen = (category + 1) % 5 if sample == 0 else category
            probabilities = tuple(0.7 if column == chosen else 0.075 for column in range(5))
            rows.append(
                SeverityEvaluationCase(
                    case_id=canonical_hash((partition, index)),
                    identity=identity(partition, index),
                    source_review_sha256=canonical_hash(("authored-review", partition, index)),
                    annotation_sha256=canonical_hash(("authored-label", partition, index)),
                    prediction_sha256=canonical_hash(("authored-numeric", partition, index)),
                    cohort="synthetic",
                    vendor="cisco" if sample % 2 else "juniper",
                    device_role="numeric_fixture",
                    anomaly_truth=True,
                    severity_truth=label,
                    probabilities=probabilities,
                )
            )
    return tuple(rows)


def numeric_batch(*, evaluation=False, per_class=3):
    reserved = numeric_cases("reserved", per_class)
    protocol = SeverityEvaluationProtocol(
        purpose="independent_test" if evaluation else "validation_diagnostic",
        target_semantics="injected_mutation",
        score_provenance="authored_numeric_fixture",
        model_version="authored-numeric-producer-0.1.0",
        model_sha256=canonical_hash("authored-numeric-producer"),
        dataset_manifest_sha256=canonical_hash("numeric-fixture-manifest"),
        annotation_manifest_sha256=canonical_hash("numeric-fixture-annotations"),
        threshold_policy_sha256=canonical_hash("initial-0.5"),
        train=(identity("train", 0),),
        selection=(identity("selection", 0),),
        reserved_test=tuple(case.identity for case in reserved),
    )
    return SeverityEvaluationBatch(
        protocol=protocol,
        cases=reserved if evaluation else numeric_cases("calibration", per_class),
    )


def fit(batch=None):
    return fit_severity_calibration(
        batch or numeric_batch(), policy=CalibrationPolicy(minimum_class_support=2)
    )


def test_actual_numerical_fit_apply_and_report_preserve_raw_predictions_and_semantics():
    calibration, evaluation = numeric_batch(), numeric_batch(evaluation=True)
    originals = (calibration.model_dump_json(), evaluation.model_dump_json())
    artifact = fit(calibration)
    transformed = apply_severity_calibration(evaluation, artifact, calibration_input=calibration)
    assert artifact.calibrated_multiclass_nll <= artifact.original_multiclass_nll
    assert tuple(item.label for item in artifact.operating_points) == SEVERITY_CLASSES
    assert all(
        item.positive_cases == 3 and item.negative_cases == 12 for item in artifact.operating_points
    )
    assert transformed.protocol.application_input_sha256 == severity_batch_identity(evaluation)
    assert transformed.protocol.calibration_sha256 == severity_artifact_identity(artifact)
    assert transformed.protocol.class_thresholds == tuple(
        point.threshold for point in artifact.operating_points
    )
    assert (calibration.model_dump_json(), evaluation.model_dump_json()) == originals
    for before, after in zip(evaluation.cases, transformed.cases, strict=True):
        assert before.model_dump(exclude={"probabilities"}) == after.model_dump(
            exclude={"probabilities"}
        )
        assert sum(after.probabilities) == pytest.approx(1.0)
    report = evaluate_severity(transformed)
    assert report.identity_holdout_checked
    assert (
        report.physical_independence_proven
        is report.online_risk_updated
        is report.risk_fused
        is False
    )
    assert report.production_quality_proven is False
    assert report.cohorts["real_confirmed"].status == "missing"
    assert report.cohorts["real_confirmed"].summary is None
    assert report.cohorts["synthetic"].summary.cases == 15
    assert report.cohorts["synthetic"].summary.declared_unique_devices == 1
    assert len(report.cohorts["synthetic"].summary.classes) == 5
    assert report.cohorts["synthetic"].summary.top_label_reliability.ece >= 0


def test_shared_temperature_preserves_zero_endpoints_and_identity_exactly():
    values = np.asarray([[1.0, 0.0, 0.0, 0.0, 0.0], [0.0, 0.1, 0.2, 0.3, 0.4]])
    assert np.array_equal(_scaled(values, 1.0), values)
    for temperature in (0.1, 0.25, 0.5, 2.0, 10.0):
        scaled = _scaled(values, temperature)
        assert np.array_equal(scaled[0], values[0])
        assert np.array_equal(scaled[values == 0], values[values == 0])
        assert np.isfinite(scaled).all()
        assert scaled.sum(axis=1) == pytest.approx([1.0, 1.0])
    assert np.array_equal(values, _scaled(values, 1.0))


def test_insufficient_default_support_is_refusal_not_identity_success():
    with pytest.raises(ValueError, match="support"):
        fit_severity_calibration(numeric_batch())


@pytest.mark.parametrize("dimension", tuple(Identity.model_fields))
@pytest.mark.parametrize("partition", ["train", "selection", "reserved_test"])
def test_fit_refuses_every_exposure_dimension(dimension, partition):
    batch = numeric_batch()
    source = getattr(batch.protocol, partition)[0]
    changed = batch.cases[0].model_copy(
        update={
            "identity": batch.cases[0].identity.model_copy(
                update={dimension: getattr(source, dimension)}
            )
        }
    )
    copied = batch.model_copy(update={"cases": (changed, *batch.cases[1:])})
    with pytest.raises(ValueError):
        fit(copied)


def test_reserved_test_cannot_be_relabelled_diagnostic_or_used_for_fit():
    batch = numeric_batch(evaluation=True)
    with pytest.raises(ValueError):
        fit(batch)
    changed = batch.model_copy(
        update={"protocol": batch.protocol.model_copy(update={"purpose": "validation_diagnostic"})}
    )
    with pytest.raises(ValueError):
        fit(changed)


def test_independent_test_rejects_a_convenient_subset_of_reserved_predictions():
    batch = numeric_batch(evaluation=True)
    with pytest.raises(ValueError, match="complete reservation"):
        evaluate_severity(batch.model_copy(update={"cases": batch.cases[:-1]}))


@pytest.mark.parametrize(
    "field",
    ["model_sha256", "model_version", "dataset_manifest_sha256", "annotation_manifest_sha256"],
)
def test_apply_refuses_changed_producer_corpus_or_annotation_binding(field):
    calibration, evaluation = numeric_batch(), numeric_batch(evaluation=True)
    value = "different" if field == "model_version" else canonical_hash("changed")
    changed = evaluation.model_copy(
        update={"protocol": evaluation.protocol.model_copy(update={field: value})}
    )
    with pytest.raises(ValueError, match="binding"):
        apply_severity_calibration(changed, fit(calibration), calibration_input=calibration)


def test_apply_recomputes_retained_calibration_not_test_and_refuses_repeated_application():
    calibration, evaluation = numeric_batch(), numeric_batch(evaluation=True)
    artifact = fit(calibration)
    altered = artifact.model_copy(
        update={"temperature": 1.0 if artifact.temperature != 1.0 else 2.0}
    )
    with pytest.raises(ValueError, match="reproduce"):
        apply_severity_calibration(evaluation, altered, calibration_input=calibration)
    changed = calibration.cases[0].model_copy(
        update={"annotation_sha256": canonical_hash("different-reviewed-label")}
    )
    with pytest.raises(ValueError, match="reproduce"):
        apply_severity_calibration(
            evaluation,
            artifact,
            calibration_input=calibration.model_copy(
                update={"cases": (changed, *calibration.cases[1:])}
            ),
        )
    applied = apply_severity_calibration(evaluation, artifact, calibration_input=calibration)
    with pytest.raises(ValueError, match="already"):
        apply_severity_calibration(applied, artifact, calibration_input=calibration)


@pytest.mark.parametrize(
    "change",
    [
        {"severity_truth": None},
        {"anomaly_truth": False},
        {"probabilities": (True, 0.0, 0.0, 0.0, 0.0)},
    ],
)
def test_copied_invalid_private_case_refused_without_serializer_warning(change, recwarn):
    batch = numeric_batch()
    changed = batch.cases[0].model_copy(update=change)
    with pytest.raises(ValueError):
        fit(batch.model_copy(update={"cases": (changed, *batch.cases[1:])}))
    assert not recwarn


def test_case_order_has_no_effect_on_numeric_calibrator_or_identity():
    batch = numeric_batch()
    reversed_batch = batch.model_copy(update={"cases": tuple(reversed(batch.cases))})
    assert severity_batch_identity(batch) == severity_batch_identity(reversed_batch)
    assert fit(batch) == fit(reversed_batch)


def test_missing_role_does_not_merge_with_a_literal_unrecorded_role_or_publish_group_keys():
    batch = numeric_batch(evaluation=True)
    cases = (
        batch.cases[0].model_copy(update={"device_role": None}),
        batch.cases[1].model_copy(update={"device_role": "unrecorded"}),
        *batch.cases[2:],
    )
    report = evaluate_severity(batch.model_copy(update={"cases": cases}))
    roles = report.cohorts["synthetic"].by_role
    assert roles["<unrecorded>"].cases == roles["unrecorded"].cases == 1
    assert report.protocol.exposure_counts == {
        "train": 1,
        "selection": 1,
        "calibration": 0,
        "reserved_test": 15,
    }
    raw = report.model_dump_json()
    for group in (batch.protocol.train, batch.protocol.selection, batch.protocol.reserved_test):
        for identity in group:
            for name in Identity.model_fields:
                assert getattr(identity, name) not in raw


def test_authored_numeric_semantics_requires_no_invented_training_but_cannot_claim_real_data():
    batch = numeric_batch()
    protocol = batch.protocol.model_copy(
        update={"target_semantics": "authored_severity_fixture", "train": (), "selection": ()}
    )
    declared = SeverityEvaluationBatch(protocol=protocol, cases=batch.cases)
    assert fit(declared).protocol.train == ()
    with pytest.raises(ValueError):
        SeverityEvaluationBatch(
            protocol=protocol,
            cases=(batch.cases[0].model_copy(update={"cohort": "real_confirmed"}),),
        )
    with pytest.raises(ValueError, match="training exposure"):
        SeverityEvaluationProtocol.model_validate(
            {
                **protocol.model_dump(),
                "score_provenance": "trained_severity_head",
                "target_semantics": "confirmed_anomaly",
                "tokenizer_sha256": canonical_hash("tokenizer"),
                "training_report_sha256": canonical_hash("training-report"),
            }
        )
