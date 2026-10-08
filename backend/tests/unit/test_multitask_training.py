"""Source-bound supervised training, deterministic frozen encoder and saved outputs."""

import json
from dataclasses import replace

import pytest
import torch
from pydantic import ValidationError

from ml.datasets import DatasetSplit
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    FineTunePolicy,
    MultiTaskReport,
    SupervisedAnnotation,
    SupervisedExample,
    extract_aligned_features,
    load_multitask,
    predict_multitask,
    save_multitask,
    train_multitask,
)
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model


@pytest.mark.parametrize(
    "payload,error",
    [
        ({}, "union_tag_not_found"),
        ({"version": "multitask-training-0.3.0"}, "union_tag_invalid"),
        ({"version": None}, "union_tag_invalid"),
        ({"version": 1}, "union_tag_invalid"),
    ],
)
def test_report_union_requires_explicit_known_version_even_with_named_alias(payload, error):
    from ml.training.multitask_training import _REPORT

    with pytest.raises(ValidationError) as failure:
        _REPORT.validate_python(payload)
    assert failure.value.errors()[0]["type"] == error


@pytest.fixture(scope="module")
def inputs():
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=16)
    )
    encoder = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    examples = authored_supervision(
        splits, (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    )
    return splits, encoder, examples


def train(inputs, **updates):
    splits, encoder, examples = inputs
    values = dict(
        head_policy=HeadPolicy(classes=("telnet_enabled", "aaa_disabled"), embedding_size=8),
        training_policy=FineTunePolicy(epochs=4),
        loss_weights=LossWeights(severity=0, contrastive=0.1),
    )
    values.update(updates)
    return train_multitask(splits, encoder, examples, **values)


def test_joint_training_restores_process_state_and_preserves_encoder(inputs, tmp_path):
    _, encoder, examples = inputs
    before = {key: value.clone() for key, value in encoder.model.state_dict().items()}
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    result = train(inputs)
    second = train(inputs)
    assert result.report == second.report
    assert all(
        torch.equal(value, second.heads.state_dict()[key])
        for key, value in result.heads.state_dict().items()
    )
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert all(torch.equal(value, encoder.model.state_dict()[key]) for key, value in before.items())
    assert result.report.encoder_frozen and not result.report.test_evaluated
    assert result.report.losses[-1].train_total < result.report.losses[0].train_total
    assert result.report.parameter_count > result.report.trainable_parameters > 0
    assert result.report.supervised_counts["severity"] == 0
    assert result.report.loss_weights.severity == 0
    assert result.report.target_semantics == "injected_mutation"
    from ml.evaluation.metrics import evaluate
    from ml.evaluation.multitask_validation import build_multitask_validation

    validation = evaluate(build_multitask_validation(result, inputs[0], examples))
    assert validation.independent_test is False
    assert (
        validation.cohorts["synthetic"].summary.configurations == result.report.validation_examples
    )
    assert validation.cohorts["synthetic"].summary.localization.annotated_cases > 0
    assert validation.cohorts["real_confirmed"].summary is None
    prediction = predict_multitask(result, examples[0].record)
    assert 0 <= prediction.anomaly_score <= 1
    assert set(prediction.category_scores) == set(result.report.head_policy.classes)
    assert prediction.severity_scores is None  # Untrained head is not shown as a severity estimate.
    assert prediction.embedding is not None and len(prediction.embedding) == 8
    assert len(prediction.line_scores) == len(examples[0].record.sanitized_text.splitlines())
    assert prediction.calibrated is False and prediction.production_quality_proven is False
    bundle = tmp_path / "model"
    save_multitask(result, bundle)
    restored = load_multitask(bundle)
    assert predict_multitask(restored, examples[0].record) == prediction
    with pytest.raises(FileExistsError):
        save_multitask(result, bundle)
    (bundle / "heads.json").write_text("{}")
    with pytest.raises(ValueError, match="checksum"):
        load_multitask(bundle)


def test_all_terms_train_with_explicit_authored_severity_not_inferred_detector_risk(inputs):
    splits, encoder, examples = inputs
    reviewed = tuple(
        replace(
            example,
            annotation=example.annotation.model_copy(
                update={"severity": "high" if example.annotation.anomaly else None}
            ),
        )
        for example in examples
    )
    result = train_multitask(
        splits,
        encoder,
        reviewed,
        head_policy=HeadPolicy(classes=("telnet_enabled", "aaa_disabled")),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(),
    )
    assert result.report.supervised_counts["severity"] > 0
    scores = predict_multitask(result, reviewed[0].record).severity_scores
    assert set(scores) == {"info", "low", "medium", "high", "critical"}
    assert sum(scores.values()) == pytest.approx(1)


def test_bound_annotations_and_original_split_membership_are_required(inputs):
    splits, encoder, examples = inputs
    first = examples[0]
    changes = (
        replace(first, parent_sha256="0" * 64),
        replace(first, annotation=first.annotation.model_copy(update={"source_sha256": "0" * 64})),
        replace(first, record=first.record.model_copy(update={"site_id": "foreign-site"})),
    )
    for changed in changes:
        with pytest.raises(ValueError):
            train_multitask(
                splits,
                encoder,
                (changed, *examples[1:]),
                head_policy=HeadPolicy(classes=("telnet_enabled", "aaa_disabled")),
                loss_weights=LossWeights(severity=0),
            )
    test = next(part for part in splits.partitions if part.split is DatasetSplit.TEST).records[0]
    annotation = SupervisedAnnotation(
        source_review_sha256="2" * 64,
        source_sha256=test.sanitized_sha256,
        annotation_sha256="0" * 64,
        origin="synthetic",
        target_semantics="injected_mutation",
        anomaly=False,
        category_targets=(0, 0),
    )
    with pytest.raises(ValueError, match="test"):
        train_multitask(
            splits,
            encoder,
            (*examples, SupervisedExample(test, test.sanitized_sha256, annotation)),
            head_policy=HeadPolicy(classes=("telnet_enabled", "aaa_disabled")),
        )


def test_labels_unknown_counts_and_dataset_limits_do_not_silently_truncate(inputs):
    with pytest.raises(ValueError, match="severity"):
        train(inputs, loss_weights=LossWeights())
    with pytest.raises(ValueError, match="budget"):
        train(inputs, training_policy=FineTunePolicy(epochs=1, max_total_windows=1))
    with pytest.raises(ValueError, match="budget"):
        train(
            inputs,
            head_policy=HeadPolicy(classes=("telnet_enabled", "aaa_disabled"), max_examples=2),
        )


@pytest.mark.parametrize("damage", ("incomplete", "extra", "count", "shape", "nan", "total"))
def test_local_bundle_rejects_tampering_even_with_recomputed_payload_checksum(
    inputs, tmp_path, damage
):
    result = train(inputs, training_policy=FineTunePolicy(epochs=1))
    bundle = tmp_path / "model"
    save_multitask(result, bundle)
    if damage in ("incomplete", "extra"):
        (bundle / (".incomplete" if damage == "incomplete" else "unexpected.txt")).write_text(
            "extra"
        )
    else:
        payload = json.loads((bundle / "heads.json").read_text())
        if damage == "count":
            payload["report"]["trainable_parameters"] += 1
        elif damage == "shape":
            payload["weights"]["category.weight"] = [[0.0]]
        elif damage == "nan":
            payload["weights"]["category.weight"][0][0] = float("nan")
        else:
            payload["report"]["losses"][0]["validation_total"] += 100
        text = json.dumps(payload)
        (bundle / "heads.json").write_text(text)
        (bundle / "heads.sha256").write_text(digest(text))
    with pytest.raises((ValueError, RuntimeError)):
        load_multitask(bundle)


def test_failed_training_restores_state_and_mutable_report_copies_revalidate(inputs):
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    with pytest.raises(ValueError, match="budget"):
        train(inputs, training_policy=FineTunePolicy(epochs=1, max_total_windows=1))
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    result = train(inputs, training_policy=FineTunePolicy(epochs=1))
    for updates in (
        {"best_epoch": 2},
        {"supervised_counts": {"anomaly": 1}},
        {"origin_counts": {"synthetic": -1}},
    ):
        forged = result.report.model_copy(update=updates)
        with pytest.raises(ValueError):
            MultiTaskReport.model_validate(forged.model_dump())


def test_feature_alignment_handles_multiwindow_lines_blank_lines_and_no_metadata_features(inputs):
    _, encoder, examples = inputs
    record = examples[0].record
    first = extract_aligned_features(record, encoder, max_windows=1000)
    renamed = record.model_copy(
        update={"device_id": "different", "device_role": "foreign", "site_id": "foreign"}
    )
    second = extract_aligned_features(renamed, encoder, max_windows=1000)
    assert torch.equal(first.blocks, second.blocks) and torch.equal(first.lines, second.lines)
    assert first.blocks.shape[1] == first.lines.shape[1] == 16
    assert first.line_numbers == tuple(sorted(set(first.line_numbers)))
    assert len(first.line_numbers) == len(first.lines)
    with pytest.raises(ValueError, match="mode"):
        encoder.model.train()
        try:
            extract_aligned_features(record, encoder, max_windows=1000)
        finally:
            encoder.model.eval()


@pytest.mark.parametrize(
    "updates",
    [
        {"anomaly": "false"},
        {"category_targets": (2,)},
        {"anomaly": False, "category_targets": (1,)},
        {"anomaly": False, "severity": "low"},
        {"severity": "unknown"},
        {"positive_lines": (0,)},
        {"positive_lines": (1, 1)},
        {"positive_lines": (2,), "ignored_lines": (2,)},
        {"anomaly": False, "positive_lines": (1,)},
        {"origin": "real_confirmed", "target_semantics": "injected_mutation"},
        {"deletion_only": True, "localization_reviewed": False},
        {"localization_reviewed": False, "positive_lines": (1,)},
    ],
)
def test_strict_annotation_contract(updates):
    values = dict(
        source_review_sha256="2" * 64,
        source_sha256="0" * 64,
        annotation_sha256="1" * 64,
        origin="synthetic",
        target_semantics="injected_mutation",
        anomaly=True,
        category_targets=(1,),
    )
    values.update(updates)
    with pytest.raises(ValueError):
        SupervisedAnnotation(**values)
