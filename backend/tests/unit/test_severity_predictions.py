"""Retained binding fixtures are not trained-head inference or calibration quality."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from app.domain import Vendor

from ml.datasets import ImportedDatasetRecord
from ml.evaluation.metrics import canonical_hash
from ml.evaluation.probe_validation import _identity
from ml.evaluation.severity_contracts import SeverityEvaluationProtocol
from ml.evaluation.severity_predictions import (
    RetainedSeverityPrediction,
    build_retained_severity_batch,
)
from ml.preprocessing.blocks import digest
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_training import (
    FineTunePolicy,
    MultiTaskPrediction,
    MultiTaskReport,
    SupervisedAnnotation,
    SupervisedEpoch,
    SupervisedExample,
    _fingerprint,
)


def example(name):
    text = f"hostname owned-{name}\nip ssh version 1\n"
    record = ImportedDatasetRecord(
        source_id="declared-unit-source",
        record_id=name,
        device_id=name,
        site_id=name,
        network_id=name,
        captured_at=datetime(2020, 1, 1, tzinfo=UTC),
        vendor_hint=Vendor.CISCO,
        device_role="test",
        raw_sha256=digest(text),
        sanitized_sha256=digest(text),
        sanitized_text=text,
        raw_byte_count=len(text),
        replacements={},
        sanitization_version="config-sanitizer-0.1.0",
    )
    return SupervisedExample(
        record,
        canonical_hash(("family", name)),
        SupervisedAnnotation(
            source_sha256=digest(text),
            annotation_sha256=canonical_hash(("annotation", name)),
            source_review_sha256=canonical_hash(("review", name)),
            origin="synthetic",
            target_semantics="injected_mutation",
            anomaly=True,
            category_targets=(1,),
            severity="high",
        ),
    )


def retained_fixture(*, disabled=False):
    train, selection, current, reserved = (
        example(name) for name in ("train", "selection", "current", "reserved")
    )
    task = "anomaly" if disabled else "severity"
    counts = {name: int(name == task) for name in LossWeights.model_fields}
    components = {name: 1.0 if name == task else None for name in LossWeights.model_fields}
    report = MultiTaskReport(
        head_policy=HeadPolicy(classes=("management",)),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(
            **{name: float(name == task) for name in LossWeights.model_fields}
        ),
        encoder_sha256=canonical_hash("declared-unit-encoder"),
        tokenizer_sha256=canonical_hash("unit-tokenizer"),
        train_fingerprint=_fingerprint((train,)),
        validation_fingerprint=_fingerprint((selection,)),
        target_semantics="injected_mutation",
        origin_counts={"synthetic": 2},
        train_examples=1,
        validation_examples=1,
        trainable_parameters=1,
        parameter_count=2,
        supervised_counts=counts,
        validation_supervised_counts=counts,
        losses=(
            SupervisedEpoch(
                epoch=1,
                train_total=1.0,
                validation_total=1.0,
                train_components=components,
                validation_components=components,
            ),
        ),
        best_epoch=1,
        torch_version="declared-unit-report-no-execution",
    )
    protocol = SeverityEvaluationProtocol(
        purpose="validation_diagnostic",
        target_semantics="injected_mutation",
        score_provenance="trained_severity_head",
        model_version=report.version,
        model_sha256=canonical_hash("declared-retained-unit-model"),
        tokenizer_sha256=report.tokenizer_sha256,
        training_report_sha256=canonical_hash(report.model_dump(mode="json")),
        dataset_manifest_sha256=canonical_hash("externally-retained-test-manifest"),
        annotation_manifest_sha256=canonical_hash("externally-retained-test-annotations"),
        threshold_policy_sha256=canonical_hash("initial-0.5"),
        train=(_identity(train.record, train.parent_sha256),),
        selection=(_identity(selection.record, selection.parent_sha256),),
        reserved_test=(_identity(reserved.record, reserved.parent_sha256),),
    )
    prediction = MultiTaskPrediction(
        source_sha256=current.record.sanitized_sha256,
        model_sha256=protocol.model_sha256,
        anomaly_score=None,
        category_scores=None,
        severity_scores=dict(zip(protocol.classes, (0.1, 0.1, 0.1, 0.6, 0.1), strict=True)),
        line_scores=(None, None),
        embedding=None,
        block_attention=(1.0,),
    )
    return protocol, dict(
        training_report=report,
        train=(train,),
        selection=(selection,),
        rows=(RetainedSeverityPrediction(current, prediction),),
    )


def test_retained_severity_adapter_preserves_exact_bindings_and_does_not_invoke_model(monkeypatch):
    from ml.training import multitask_training

    def no_model(*args, **kwargs):
        pytest.fail("retained adapter executed or loaded model weights")

    monkeypatch.setattr(multitask_training, "predict_multitask", no_model)
    monkeypatch.setattr(multitask_training, "load_multitask", no_model)
    protocol, inputs = retained_fixture()
    raw = inputs["rows"][0]
    before = raw.prediction.model_dump_json()
    result = build_retained_severity_batch(protocol, **inputs)
    assert result.protocol == protocol and len(result.cases) == 1
    case = result.cases[0]
    assert case.prediction_sha256 == canonical_hash(raw.prediction.model_dump(mode="json"))
    assert case.identity == _identity(raw.example.record, raw.example.parent_sha256)
    assert case.annotation_sha256 == raw.example.annotation.annotation_sha256
    assert case.severity_truth == "high" and case.probabilities == (0.1, 0.1, 0.1, 0.6, 0.1)
    assert raw.prediction.model_dump_json() == before
    assert raw.example.record.sanitized_text not in repr(raw)
    assert "owned-current" not in repr(result)


@pytest.mark.parametrize(
    "change",
    [
        "text",
        "source",
        "model",
        "unknown",
        "healthy",
        "disabled_prediction",
        "missing_class",
        "extra_class",
        "bool_score",
        "string_score",
        "nan",
        "unnormalized",
        "calibrated_copy",
        "lines",
        "vendor",
        "empty_metadata",
        "naive_time",
    ],
)
def test_any_invalid_retained_row_refuses_whole_batch_without_private_error(change, recwarn):
    protocol, inputs = retained_fixture()
    row = inputs["rows"][0]
    current, prediction = row.example, row.prediction
    if change == "text":
        current = replace(
            current,
            record=current.record.model_copy(update={"sanitized_text": "PRIVATE-ADAPTER-MARKER"}),
        )
    elif change == "source":
        prediction = prediction.model_copy(update={"source_sha256": "0" * 64})
    elif change == "model":
        prediction = prediction.model_copy(update={"model_sha256": "0" * 64})
    elif change == "unknown":
        current = replace(
            current, annotation=current.annotation.model_copy(update={"severity": None})
        )
    elif change == "healthy":
        current = replace(
            current,
            annotation=current.annotation.model_copy(
                update={"anomaly": False, "severity": None, "category_targets": (0,)}
            ),
        )
    elif change == "disabled_prediction":
        prediction = prediction.model_copy(update={"severity_scores": None})
    elif change in (
        "missing_class",
        "extra_class",
        "bool_score",
        "string_score",
        "nan",
        "unnormalized",
    ):
        scores = dict(prediction.severity_scores)
        if change == "missing_class":
            scores.pop("info")
        elif change == "extra_class":
            scores["unknown"] = 0.0
        elif change == "unnormalized":
            scores = dict.fromkeys(protocol.classes, 0.3)
        else:
            scores["info"] = {"bool_score": True, "string_score": "0.1", "nan": float("nan")}[
                change
            ]
        prediction = prediction.model_copy(update={"severity_scores": scores})
    elif change == "calibrated_copy":
        prediction = prediction.model_copy(update={"calibrated": 0})
    elif change == "lines":
        prediction = prediction.model_copy(update={"line_scores": (None,)})
    elif change == "vendor":
        current = replace(current, record=current.record.model_copy(update={"vendor_hint": None}))
    elif change == "empty_metadata":
        current = replace(current, record=current.record.model_copy(update={"site_id": ""}))
    else:
        current = replace(
            current, record=current.record.model_copy(update={"captured_at": datetime(2020, 1, 1)})
        )
    with pytest.raises(ValueError) as error:
        build_retained_severity_batch(
            protocol, **(inputs | {"rows": (RetainedSeverityPrediction(current, prediction),)})
        )
    assert str(error.value) == "Retained severity prediction binding is unavailable."
    assert not recwarn


@pytest.mark.parametrize(
    "change",
    [
        "report",
        "tokenizer",
        "train_annotation",
        "train_exposure",
        "train_count",
        "selection_count",
        "reserved",
        "disabled_report",
    ],
)
def test_report_model_and_exact_training_selection_or_reservation_bindings_are_required(change):
    protocol, inputs = retained_fixture(disabled=change == "disabled_report")
    if change in ("report", "tokenizer"):
        key = "training_report_sha256" if change == "report" else "tokenizer_sha256"
        protocol = protocol.model_copy(update={key: "0" * 64})
    elif change == "train_annotation":
        current = inputs["train"][0]
        inputs["train"] = (
            replace(
                current, annotation=current.annotation.model_copy(update={"severity": "medium"})
            ),
        )
    elif change == "train_exposure":
        current = inputs["train"][0]
        inputs["train"] = (
            replace(current, record=current.record.model_copy(update={"device_id": "changed"})),
        )
    elif change in ("train_count", "selection_count"):
        inputs[change.removesuffix("_count")] = ()
    elif change == "reserved":
        row = inputs["rows"][0]
        protocol = protocol.model_copy(
            update={"reserved_test": (_identity(row.example.record, row.example.parent_sha256),)}
        )
    with pytest.raises(ValueError, match="unavailable"):
        build_retained_severity_batch(protocol, **inputs)


@pytest.mark.parametrize("partition", ["train", "selection"])
@pytest.mark.parametrize("reported_support", [1, 2])
def test_retained_labels_must_reproduce_reported_severity_support(partition, reported_support):
    protocol, inputs = retained_fixture()
    original = inputs[partition][0]
    # A self-consistent fingerprint alone must not hide missing supervision.
    inputs[partition] = (
        replace(original, annotation=original.annotation.model_copy(update={"severity": None})),
    )
    report = inputs["training_report"]
    count_field = "supervised_counts" if partition == "train" else "validation_supervised_counts"
    fingerprint_field = "train_fingerprint" if partition == "train" else "validation_fingerprint"
    report = report.model_copy(
        update={
            count_field: report.model_dump()[count_field] | {"severity": reported_support},
            fingerprint_field: _fingerprint(inputs[partition]),
        }
    )
    inputs["training_report"] = report
    protocol = protocol.model_copy(
        update={"training_report_sha256": canonical_hash(report.model_dump(mode="json"))}
    )
    with pytest.raises(ValueError, match="unavailable"):
        build_retained_severity_batch(protocol, **inputs)


@pytest.mark.parametrize("partition", ["train", "selection"])
def test_nonzero_retained_support_must_equal_reported_count(partition):
    protocol, inputs = retained_fixture()
    report = inputs["training_report"]
    field = "supervised_counts" if partition == "train" else "validation_supervised_counts"
    report = report.model_copy(update={field: report.model_dump()[field] | {"severity": 2}})
    inputs["training_report"] = report
    protocol = protocol.model_copy(
        update={"training_report_sha256": canonical_hash(report.model_dump(mode="json"))}
    )
    with pytest.raises(ValueError, match="unavailable"):
        build_retained_severity_batch(protocol, **inputs)
