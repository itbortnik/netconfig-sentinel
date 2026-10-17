"""Severity inputs preserve five-class semantics, provenance and exposure boundaries."""

from __future__ import annotations

from hashlib import sha256
from itertools import combinations

import pytest
from pydantic import ValidationError

from ml.evaluation.contracts import EvaluationProtocol, Identity
from ml.evaluation.severity_contracts import (
    SEVERITY_CLASSES,
    SeverityEvaluationBatch,
    SeverityEvaluationCase,
    SeverityEvaluationProtocol,
)


def digest(value):
    return sha256(str(value).encode()).hexdigest()


def identity(value):
    return Identity(**{field: digest(field + str(value)) for field in Identity.model_fields})


def protocol_data(**updates):
    values = {
        "purpose": "independent_test",
        "target_semantics": "confirmed_anomaly",
        "score_provenance": "authored_numeric_fixture",
        "model_version": "numeric-fixture-1",
        "model_sha256": digest("numeric-fixture"),
        "dataset_manifest_sha256": digest("dataset-manifest"),
        "annotation_manifest_sha256": digest("annotation-manifest"),
        "threshold_policy_sha256": digest("threshold-policy"),
        "train": (identity("train"),),
        "reserved_test": (identity("reserved"),),
    }
    values.update(updates)
    return values


def protocol(**updates):
    return SeverityEvaluationProtocol(**protocol_data(**updates))


def case_data(value="case", **updates):
    values = {
        "case_id": digest(value),
        "identity": identity(value),
        "source_review_sha256": digest("source-review-" + str(value)),
        "annotation_sha256": digest("annotation-" + str(value)),
        "prediction_sha256": digest("prediction-" + str(value)),
        "cohort": "synthetic",
        "vendor": "cisco",
        "anomaly_truth": True,
        "severity_truth": "high",
        "probabilities": (0.0, 0.1, 0.2, 0.6, 0.1),
    }
    values.update(updates)
    return values


def case(value="case", **updates):
    return SeverityEvaluationCase(**case_data(value, **updates))


def all_exposures():
    return protocol_data(
        selection=(identity("selection"),),
        calibration=(identity("calibration"),),
        calibration_sha256=digest("calibrator"),
        application_input_sha256=digest("raw-input"),
    )


def test_protocol_is_explicit_and_keeps_a_fixed_five_class_catalog():
    value = protocol()
    assert value.version == "severity-evaluation-0.1.0"
    assert value.task == "anomaly_severity"
    assert value.classes == SEVERITY_CLASSES == ("info", "low", "medium", "high", "critical")
    assert value.class_thresholds == (0.5,) * 5
    assert value.score_kind == "probability"
    assert value.reliability_bins == 10
    assert value.tokenizer_sha256 is value.training_report_sha256 is None
    assert value.calibration_sha256 is value.application_input_sha256 is None
    assert value.selection == value.calibration == ()
    assert value.reserved_test == (identity("reserved"),)


@pytest.mark.parametrize(
    "required",
    [
        "purpose",
        "target_semantics",
        "score_provenance",
        "model_version",
        "model_sha256",
        "dataset_manifest_sha256",
        "annotation_manifest_sha256",
        "threshold_policy_sha256",
        "train",
        "reserved_test",
    ],
)
def test_protocol_refuses_missing_provenance_and_reserved_identities(required):
    value = protocol_data()
    del value[required]
    with pytest.raises(ValidationError):
        SeverityEvaluationProtocol.model_validate(value)


@pytest.mark.parametrize("label", SEVERITY_CLASSES)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_every_severity_label_accepts_endpoint_probabilities(label, vendor):
    scores = tuple(float(item == label) for item in SEVERITY_CLASSES)
    value = case(severity_truth=label, probabilities=scores, vendor=vendor)
    assert value.probabilities == scores
    assert value.severity_truth == label and value.anomaly_truth is True
    assert value.device_role is None
    assert SeverityEvaluationCase.model_validate_json(value.model_dump_json()) == value


@pytest.mark.parametrize("label", [None, "unknown", "disabled", "healthy", "safe", "severe", 4])
def test_unknown_or_risk_band_labels_are_never_substituted_for_severity(label):
    with pytest.raises(ValidationError):
        case(severity_truth=label)


@pytest.mark.parametrize("truth", [False, None, 0, 1, "true", "false"])
def test_healthy_or_unconfirmed_cases_are_not_mapped_to_info(truth):
    with pytest.raises(ValidationError):
        case(anomaly_truth=truth, severity_truth="info", probabilities=(1, 0, 0, 0, 0))


@pytest.mark.parametrize("missing", ["severity_truth", "anomaly_truth", "probabilities"])
def test_no_implicit_labels_or_predictions(missing):
    values = case_data()
    del values[missing]
    with pytest.raises(ValidationError):
        SeverityEvaluationCase.model_validate(values)


@pytest.mark.parametrize(
    "probabilities",
    [
        (),
        (0.2,) * 4,
        (0.2,) * 6,
        (0.0,) * 5,
        (0.5,) * 5,
        (float("nan"), 0.0, 0.0, 1.0, 0.0),
        (float("inf"), 0.0, 0.0, 1.0, 0.0),
        (-0.1, 0.0, 0.0, 1.0, 0.1),
        (1.1, 0.0, 0.0, 0.0, 0.0),
        (False, 0.0, 0.0, 1.0, 0.0),
        (True, 0.0, 0.0, 0.0, 0.0),
        ("0.0", 0.0, 0.0, 1.0, 0.0),
        {"info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0},
    ],
)
def test_probability_vectors_refuse_nonfinite_wrong_types_and_unnormalized_values(probabilities):
    with pytest.raises(ValidationError):
        case(probabilities=probabilities)


def test_probability_tolerance_does_not_normalize_the_supplied_scores():
    scores = (0.2, 0.2, 0.2, 0.2, 0.2000005)
    value = case(probabilities=scores)
    assert value.probabilities == scores
    assert sum(value.probabilities) != 1.0
    with pytest.raises(ValidationError, match="sum to one"):
        case(probabilities=(0.2, 0.2, 0.2, 0.2, 0.200002))


@pytest.mark.parametrize(
    "updates",
    [
        {"classes": SEVERITY_CLASSES[:-1]},
        {"classes": SEVERITY_CLASSES[::-1]},
        {"classes": ("low", "low", "medium", "high", "critical")},
        {"classes": ("safe", "low", "medium", "high", "critical")},
        {"classes": (*SEVERITY_CLASSES, "critical")},
        {"class_thresholds": (0.5,) * 4},
        {"class_thresholds": (0.5,) * 6},
        {"class_thresholds": (float("nan"),) * 5},
        {"class_thresholds": (float("inf"),) * 5},
        {"class_thresholds": (True,) * 5},
        {"class_thresholds": ("0.5",) * 5},
        {"class_thresholds": (-0.1,) * 5},
        {"class_thresholds": (1.01,) * 5},
        {"score_kind": "ranking"},
        {"task": "fused_risk"},
        {"reliability_bins": True},
        {"reliability_bins": 10.0},
        {"reliability_bins": 1},
        {"reliability_bins": 51},
        {"model_version": ""},
        {"model_version": "v" * 129},
        {"model_version": 1},
        {"score_provenance": "inferred_from_model_version"},
        {"target_semantics": "unknown"},
        {"purpose": "training"},
        {
            "train": (),
            "score_provenance": "trained_severity_head",
            "tokenizer_sha256": digest("tokenizer"),
            "training_report_sha256": digest("training-report"),
        },
        {"reserved_test": ()},
    ],
)
def test_protocol_refuses_incompatible_semantics_types_and_bounds(updates):
    with pytest.raises(ValidationError):
        protocol(**updates)


@pytest.mark.parametrize("bins", [2, 50])
def test_protocol_accepts_reliability_and_threshold_endpoints(bins):
    value = protocol(reliability_bins=bins, class_thresholds=(0, 1, 0, 1, 0.5))
    assert value.reliability_bins == bins
    assert value.class_thresholds == (0, 1, 0, 1, 0.5)


def test_trained_scores_require_both_tokenizer_and_training_report():
    value = protocol(
        score_provenance="trained_severity_head",
        tokenizer_sha256=digest("tokenizer"),
        training_report_sha256=digest("training-report"),
    )
    assert value.score_provenance == "trained_severity_head"
    for tokenizer, report in [(None, None), (None, digest("report")), (digest("tokenizer"), None)]:
        with pytest.raises(ValidationError, match="training artifacts"):
            protocol(
                score_provenance="trained_severity_head",
                tokenizer_sha256=tokenizer,
                training_report_sha256=report,
            )


@pytest.mark.parametrize("field", ["tokenizer_sha256", "training_report_sha256"])
def test_authored_numeric_fixture_cannot_claim_training_artifacts(field):
    with pytest.raises(ValidationError, match="training artifacts"):
        protocol(**{field: digest(field)})


@pytest.mark.parametrize(
    ("calibration", "calibrator", "raw_input"),
    [
        ((), None, digest("raw")),
        ((), digest("calibrator"), None),
        ((), digest("calibrator"), digest("raw")),
        ((identity("calibration"),), None, None),
        ((identity("calibration"),), digest("calibrator"), None),
        ((identity("calibration"),), None, digest("raw")),
    ],
)
def test_calibration_exposure_and_both_bindings_are_present_together(
    calibration, calibrator, raw_input
):
    with pytest.raises(ValidationError, match="bound together"):
        protocol(
            calibration=calibration,
            calibration_sha256=calibrator,
            application_input_sha256=raw_input,
        )


def test_calibration_and_application_input_are_distinct_preserved_bindings():
    value = SeverityEvaluationProtocol.model_validate(all_exposures())
    assert value.calibration_sha256 == digest("calibrator")
    assert value.application_input_sha256 == digest("raw-input")
    assert value.calibration == (identity("calibration"),)


@pytest.mark.parametrize("field", tuple(Identity.model_fields))
@pytest.mark.parametrize(
    ("first", "second"),
    list(combinations(("train", "selection", "calibration", "reserved_test"), 2)),
)
def test_all_exposure_partition_pairs_are_disjoint_in_every_identity_dimension(
    field, first, second
):
    values = all_exposures()
    values[second] = (
        values[second][0].model_copy(update={field: getattr(values[first][0], field)}),
    )
    with pytest.raises(ValidationError, match=r"exposure|unique"):
        SeverityEvaluationProtocol.model_validate(values)


@pytest.mark.parametrize("group", ["train", "selection", "calibration", "reserved_test"])
def test_each_exposure_partition_requires_unique_source_hashes(group):
    values = all_exposures()
    copied_source = identity("another").model_copy(
        update={"source_sha256": values[group][0].source_sha256}
    )
    values[group] += (copied_source,)
    with pytest.raises(ValidationError, match="unique within a partition"):
        SeverityEvaluationProtocol.model_validate(values)


@pytest.mark.parametrize("group", ["train", "selection", "calibration", "reserved_test"])
def test_views_may_share_family_device_site_network_within_a_partition(group):
    values = all_exposures()
    view = values[group][0].model_copy(update={"source_sha256": digest("view-source")})
    values[group] += (view,)
    assert len(getattr(SeverityEvaluationProtocol.model_validate(values), group)) == 2


@pytest.mark.parametrize("group", ["train", "selection", "calibration", "reserved_test"])
def test_exposure_partition_count_is_bounded(group):
    values = all_exposures()
    values[group] *= 20001
    with pytest.raises(ValidationError):
        SeverityEvaluationProtocol.model_validate(values)


@pytest.mark.parametrize(
    "field", ["case_id", "source_review_sha256", "annotation_sha256", "prediction_sha256"]
)
@pytest.mark.parametrize("value", [None, "missing", "A" * 64, "0" * 63, 1])
def test_case_artifact_bindings_are_required_sha256_digests(field, value):
    with pytest.raises(ValidationError):
        case(**{field: value})


@pytest.mark.parametrize(
    "field", ["case_id", "source_review_sha256", "annotation_sha256", "prediction_sha256"]
)
def test_case_cannot_omit_artifact_bindings(field):
    values = case_data()
    del values[field]
    with pytest.raises(ValidationError):
        SeverityEvaluationCase.model_validate(values)


@pytest.mark.parametrize("field", ["case_id", "source_sha256"])
def test_batch_requires_unique_cases_and_configuration_sources(field):
    first, second = case("first"), case("second")
    if field == "case_id":
        second = second.model_copy(update={"case_id": first.case_id})
    else:
        second = second.model_copy(
            update={
                "identity": second.identity.model_copy(
                    update={field: getattr(first.identity, field)}
                )
            }
        )
    with pytest.raises(ValidationError, match="unique"):
        SeverityEvaluationBatch(protocol=protocol(), cases=(first, second))


def test_real_confirmed_cannot_be_reported_as_injected_mutation():
    row = case(cohort="real_confirmed", vendor="juniper")
    with pytest.raises(ValidationError, match="confirmed-anomaly"):
        SeverityEvaluationBatch(
            protocol=protocol(target_semantics="injected_mutation"), cases=(row,)
        )
    assert SeverityEvaluationBatch(protocol=protocol(), cases=(row,)).cases == (row,)


@pytest.mark.parametrize("purpose", ["independent_test", "validation_diagnostic"])
def test_batch_shape_does_not_decide_fit_or_evaluation_exposure_gates(purpose):
    # Operation-specific gates decide whether train, selection, calibration or
    # reserved cases may be used. The structural contract is shared by those gates.
    value = SeverityEvaluationBatch(
        protocol=protocol(purpose=purpose), cases=(case(identity=identity("train")),)
    )
    assert value.cases[0].identity == value.protocol.train[0]


def test_batch_roles_and_case_counts_are_bounded():
    rows = tuple(case(str(index), device_role=f"role-{index}") for index in range(65))
    with pytest.raises(ValidationError, match="role slice budget"):
        SeverityEvaluationBatch(protocol=protocol(), cases=rows)
    assert len(SeverityEvaluationBatch(protocol=protocol(), cases=rows[:64]).cases) == 64
    with pytest.raises(ValidationError):
        SeverityEvaluationBatch(protocol=protocol(), cases=())
    with pytest.raises(ValidationError):
        SeverityEvaluationBatch(protocol=protocol(), cases=(case(),) * 20001)


@pytest.mark.parametrize("field", tuple(Identity.model_fields))
def test_copied_invalid_identity_is_revalidated_without_changing_shared_identity_model(field):
    invalid = identity("case").model_copy(update={field: "invalid"})
    with pytest.raises(ValidationError):
        case(identity=invalid)
    with pytest.raises(ValidationError):
        protocol(train=(invalid,))


@pytest.mark.parametrize(
    "updates",
    [
        {"anomaly_truth": False},
        {"anomaly_truth": 1},
        {"severity_truth": None},
        {"probabilities": (True, 0, 0, 0, 0)},
        {"probabilities": (float("nan"), 0, 0, 0, 1)},
        {"prediction_sha256": "invalid"},
    ],
)
def test_copied_case_is_revalidated_at_case_and_batch_boundaries(updates):
    copied = case().model_copy(update=updates)
    with pytest.raises(ValidationError):
        SeverityEvaluationCase.model_validate(copied)
    with pytest.raises(ValidationError):
        SeverityEvaluationBatch(protocol=protocol(), cases=(copied,))


def test_copied_protocol_and_batch_cannot_bypass_validation():
    copied = protocol().model_copy(update={"class_thresholds": (float("nan"),) * 5})
    with pytest.raises(ValidationError):
        SeverityEvaluationProtocol.model_validate(copied)
    with pytest.raises(ValidationError):
        SeverityEvaluationBatch(protocol=copied, cases=(case(),))
    copied = protocol().model_copy(update={"reserved_test": (identity("train"),)})
    with pytest.raises(ValidationError, match="exposure"):
        SeverityEvaluationProtocol.model_validate(copied)
    value = SeverityEvaluationBatch(protocol=protocol(), cases=(case(),))
    copied_batch = value.model_copy(update={"cases": ()})
    with pytest.raises(ValidationError):
        SeverityEvaluationBatch.model_validate(copied_batch)


def test_new_contracts_are_frozen_and_forbid_extra_scores_or_raw_configurations():
    for values, contract in [
        (protocol_data(), SeverityEvaluationProtocol),
        (case_data(), SeverityEvaluationCase),
    ]:
        with pytest.raises(ValidationError):
            contract.model_validate({**values, "raw_configuration": "hostname omitted"})
    with pytest.raises(ValidationError):
        case(detection_score=0.9)
    value = protocol()
    with pytest.raises(ValidationError):
        value.reliability_bins = 3
    assert EvaluationProtocol.model_fields["version"].default == "offline-evaluation-0.1.0"
    assert "reserved_test" not in EvaluationProtocol.model_fields
