"""Joint Stage A -> frozen Stage B, without claiming external foundation training."""

import copy
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import torch

from ml.datasets import DatasetSplit
from ml.evaluation.metrics import evaluate
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    FineTunePolicy,
    MultiTaskTransferReport,
    extract_aligned_features,
    load_multitask,
    predict_multitask,
    save_multitask,
    train_multitask,
)
from ml.training.pretraining import (
    PretrainingPolicy,
    pretraining_identity,
    train_configuration_objectives,
)
from ml.training.pretraining_data import PretrainingWeights
from ml.training.pretraining_smoke import pretraining_fixtures
from ml.training.pretraining_transfer import objective_split_identity, validate_objective_source
from ml.training.transformer import EncoderPolicy


@pytest.fixture(scope="module")
def inputs():
    splits, pairs = pretraining_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=128)
    )
    source = train_configuration_objectives(
        splits,
        tokenizer,
        semantic_pairs=pairs,
        encoder_policy=EncoderPolicy(
            hidden_size=16, layers=1, heads=2, feedforward_size=32, dropout=0
        ),
        training_policy=PretrainingPolicy(epochs=2, embedding_size=8),
        weights=PretrainingWeights(cross_vendor=0.1),
    )
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    return splits, pairs, source, examples


def train(inputs, **updates):
    splits, pairs, source, examples = inputs
    values = {
        "head_policy": HeadPolicy(classes=("telnet_enabled",), embedding_size=8, max_examples=128),
        "training_policy": FineTunePolicy(epochs=2),
        "loss_weights": LossWeights(severity=0),
        "semantic_pairs": pairs,
    }
    values.update(updates)
    return train_multitask(splits, source, examples, **values)


def test_actual_joint_source_reaches_supervised_heads_without_mlm_relabeling(inputs, tmp_path):
    splits, pairs, source, examples = inputs
    identity = pretraining_identity(source)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    mode, gradients = (
        source.model.training,
        tuple(p.requires_grad for p in source.model.parameters()),
    )
    result, repeated = train(inputs), train(inputs)
    assert isinstance(result.report, MultiTaskTransferReport)
    assert result.report.version == "multitask-training-0.2.0"
    assert result.report == repeated.report
    assert all(
        torch.equal(value, repeated.heads.state_dict()[name])
        for name, value in result.heads.state_dict().items()
    )
    assert pretraining_identity(source) == identity
    assert source.model.training == mode
    assert tuple(p.requires_grad for p in source.model.parameters()) == gradients
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert result.report.pretraining.pretraining_sha256 == identity
    assert result.report.pretraining.semantic_pairs == pairs
    assert result.report.pretraining.source_manifest_sha256 == objective_split_identity(splits)
    assert not any(p.requires_grad for p in result.pretrained.model.parameters())
    assert result.report.parameter_count == (
        result.report.trainable_parameters + source.report.parameter_count
    )
    prediction = predict_multitask(result, examples[0].record)
    assert prediction.severity_scores is None and not prediction.calibrated
    assert prediction.embedding is not None and len(prediction.embedding) == 8
    assert prediction.production_quality_proven is False
    batch = build_multitask_validation(result, splits, examples)
    report = evaluate(batch)
    assert report.cohorts["real_confirmed"].summary is None
    assert not report.independent_test and batch.protocol.model_version == result.report.version
    bundle = tmp_path / "joint"
    save_multitask(result, bundle)
    restored = load_multitask(bundle)
    assert restored.report == result.report
    assert restored.pretrained.report.version == "config-objective-pretraining-0.1.0"
    assert pretraining_identity(restored.pretrained) == identity
    assert predict_multitask(restored, examples[0].record) == prediction
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads


def test_encoder_features_use_the_trained_nested_encoder_and_keep_line_alignment(inputs):
    _, _, source, examples = inputs
    record = examples[0].record
    features = extract_aligned_features(record, source, max_windows=1000)
    assert features.blocks.shape[1] == features.lines.shape[1] == 16
    assert features.line_numbers == tuple(sorted(set(features.line_numbers)))
    assert features.total_lines == len(record.sanitized_text.splitlines())
    renamed = record.model_copy(update={"device_role": "different", "site_id": "different"})
    altered = extract_aligned_features(renamed, source, max_windows=1000)
    assert torch.equal(features.blocks, altered.blocks) and torch.equal(
        features.lines, altered.lines
    )


@pytest.mark.parametrize("damage", ["missing", "review", "truth", "scope", "test", "reverse"])
def test_objective_exposure_is_regenerated_not_only_inferred_from_source_hashes(inputs, damage):
    splits, pairs, source, _ = inputs
    first = pairs[0]
    if damage == "missing":
        changed = ()
    elif damage == "reverse":
        changed = tuple(reversed(pairs))
    elif damage == "test":
        row = next(part for part in splits.partitions if part.split is DatasetSplit.TEST).records[0]
        changed = (first.model_copy(update={"right_sha256": row.sanitized_sha256}), *pairs[1:])
    else:
        fields = {
            "review": {"review_sha256": "f" * 64},
            "truth": {"equivalent": not first.equivalent},
            "scope": {"scope": "different_scope"},
        }
        changed = (first.model_copy(update=fields[damage]), *pairs[1:])
    with pytest.raises(ValueError):
        train(inputs, semantic_pairs=changed)
    assert source.model.training is False


@pytest.mark.parametrize("damage", ["source", "validation", "counts", "tokenizer", "nan"])
def test_source_report_and_weights_are_revalidated_before_transfer(inputs, damage):
    splits, pairs, source, _ = inputs
    altered = copy.deepcopy(source)
    if damage == "nan":
        with torch.no_grad():
            altered.model.projection.bias[0] = float("nan")
    elif damage == "tokenizer":
        altered.tokenizer = altered.tokenizer.model_copy(update={"training_fingerprint": "f" * 64})
    else:
        fields = {
            "source": {"train_source_fingerprint": "f" * 64},
            "validation": {"validation_fingerprint": "f" * 64},
            "counts": {"source_counts": {"train": 1, "validation": 1}},
        }
        altered.report = altered.report.model_copy(update=fields[damage])
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    with pytest.raises(ValueError):
        validate_objective_source(splits, altered, pairs)
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads


@pytest.mark.parametrize(
    "damage", ["source_identity", "report_identity", "labels", "version", "auxiliary"]
)
def test_changed_transfer_bundle_is_rejected_even_with_recomputed_heads_checksum(
    inputs, tmp_path, damage
):
    result = train(inputs)
    bundle = tmp_path / damage
    save_multitask(result, bundle)
    payload = json.loads((bundle / "heads.json").read_text())
    if damage == "version":
        payload["report"]["version"] = "multitask-training-0.1.0"
    elif damage == "labels":
        payload["report"]["pretraining"]["semantic_pairs"][0]["review_sha256"] = "f" * 64
    elif damage == "auxiliary":
        from ml.training.checkpoint import _file_hash

        state = torch.load(bundle / "encoder/weights.pt", weights_only=True)
        state["projection.bias"][0] += 1
        torch.save(state, bundle / "encoder/weights.pt")
        manifest = json.loads((bundle / "encoder/manifest.json").read_text())
        manifest["files"]["weights.pt"] = _file_hash(bundle / "encoder/weights.pt")
        (bundle / "encoder/manifest.json").write_text(json.dumps(manifest))
    else:
        name = "pretraining_sha256" if damage == "source_identity" else "report_sha256"
        payload["report"]["pretraining"][name] = "f" * 64
    text = json.dumps(payload)
    (bundle / "heads.json").write_text(text)
    (bundle / "heads.sha256").write_text(digest(text))
    with pytest.raises(ValueError):
        load_multitask(bundle)


def test_disabled_stage_a_terms_and_stage_b_severity_are_not_manufactured(inputs):
    splits, _, source, examples = inputs
    encoder = train_configuration_objectives(
        splits,
        source.tokenizer,
        encoder_policy=source.report.encoder_policy,
        training_policy=PretrainingPolicy(epochs=1),
        weights=PretrainingWeights(command=0, parameter=0, replaced_line=0, same_device=0),
    )
    result = train((splits, (), encoder, examples))
    assert result.report.pretraining.semantic_pairs == ()
    assert result.pretrained.report.losses[0].train_components["cross_vendor"] is None
    assert predict_multitask(result, examples[0].record).severity_scores is None


def test_all_five_stage_b_terms_use_explicit_synthetic_severity_on_joint_stage_a(inputs):
    splits, pairs, source, examples = inputs
    reviewed = tuple(
        replace(
            row,
            annotation=row.annotation.model_copy(
                update={"severity": "high" if row.annotation.anomaly else None}
            ),
        )
        for row in examples
    )
    result = train((splits, pairs, source, reviewed), loss_weights=LossWeights())
    assert all(value > 0 for value in result.report.supervised_counts.values())
    assert predict_multitask(result, examples[0].record).severity_scores is not None


def test_transfer_prediction_and_validation_detect_post_training_binding_drift(inputs):
    splits, _, _, examples = inputs
    result = train(inputs)
    with torch.no_grad():
        result.pretrained.model.projection.bias[0] += 1
    with pytest.raises(ValueError, match="binding"):
        predict_multitask(result, examples[0].record)
    with pytest.raises(ValueError, match="binding"):
        build_multitask_validation(result, splits, examples)


@pytest.mark.parametrize("damage", ["dtype", "heads", "feedforward", "count"])
def test_unsupported_in_memory_model_cannot_be_transferred(inputs, damage):
    splits, pairs, source, _ = inputs
    source = copy.deepcopy(source)
    if damage == "dtype":
        source.model.double()
    elif damage == "heads":
        source.model.encoder.layers[0].self_attn.num_heads = 1
    elif damage == "feedforward":
        source.model.encoder.layers[0].linear1.out_features += 1
    else:
        source.report = source.report.model_copy(update={"parameter_count": 1})
    with pytest.raises(ValueError):
        validate_objective_source(splits, source, pairs)


def test_manually_training_nested_encoder_is_not_deterministic_feature_extraction(inputs):
    _, _, source, examples = inputs
    altered = copy.deepcopy(source)
    altered.model.encoder.train()
    assert not altered.model.training
    with pytest.raises(ValueError, match="evaluation mode"):
        extract_aligned_features(examples[0].record, altered, max_windows=1000)


def test_a_different_audited_split_cannot_validate_the_transferred_model(inputs):
    from ml.training.classification_smoke import classification_fixtures

    _, _, _, examples = inputs
    with pytest.raises(ValueError, match="manifest binding"):
        build_multitask_validation(train(inputs), classification_fixtures(), examples)


def test_cli_refuses_existing_output_and_foreign_source_without_exposing_inputs(
    inputs, tmp_path, monkeypatch, capsys
):
    from ml.training.pretraining_transfer_smoke import main

    existing = tmp_path / "existing"
    existing.mkdir()
    monkeypatch.setattr("sys.argv", ["transfer", "--output", str(existing)])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert "new output directory" in capsys.readouterr().err
    monkeypatch.setattr(
        "sys.argv",
        ["transfer", "--output", str(tmp_path / "new"), "--source-model", str(tmp_path / "absent")],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert "Transfer failed" in capsys.readouterr().err
    assert not (tmp_path / "new").exists()


def test_legacy_mlm_path_rejects_instead_of_ignoring_objective_pair_labels(inputs):
    from ml.training.classification_smoke import classification_fixtures
    from ml.training.transformer import TrainingPolicy, train_masked_language_model

    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=128)
    )
    source = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, layers=1, heads=2, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    with pytest.raises(ValueError, match="cannot silently ignore"):
        train_multitask(
            splits,
            source,
            examples,
            semantic_pairs=inputs[1],
            head_policy=HeadPolicy(classes=("telnet_enabled",)),
        )


def test_split_identity_survives_other_process_hash_seeds(inputs, tmp_path):
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from ml.training.pretraining_smoke import pretraining_fixtures; "
        "from ml.training.pretraining_transfer import objective_split_identity; "
        "print(objective_split_identity(pretraining_fixtures()[0]))"
    )
    expected = objective_split_identity(inputs[0])
    project_root = Path(__file__).resolve().parents[3]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    }
    for seed in ("1", "2", "3"):
        environment["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", code, str(project_root)],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        assert result.stdout.strip() == expected
