"""Actual fixture encoder transfer, full exposure refusal and historical format boundaries."""

import copy
import json
from dataclasses import replace

import pytest
import torch
from pydantic import ValidationError
from test_fixture_pretraining import ENCODER, TOKENIZER, TRAINING, owned_inputs

from ml.datasets import DatasetSplit
from ml.datasets.deduplication import _jaccard_similarity, _prepare_record
from ml.datasets.fixture_training import FixtureTrainingPolicy, prepare_fixture_training_corpus
from ml.evaluation.metrics import evaluate
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import train_fixture_tokenizer
from ml.registry.store import initialize_registry, register_model
from ml.training.fixture_transfer import (
    FixtureExposureAudit,
    FixtureTransferPolicy,
    audit_fixture_exposure,
    validate_fixture_source,
)
from ml.training.fixture_transfer_smoke import authored_transfer_splits, run_fixture_transfer
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    FineTunePolicy,
    MultiTaskFixtureTransferReport,
    extract_aligned_features,
    load_multitask,
    multitask_identity,
    predict_multitask,
    save_multitask,
    train_multitask,
)
from ml.training.pretraining import (
    pretraining_identity,
    save_pretraining,
    train_configuration_objectives,
    train_fixture_objectives,
)


@pytest.fixture(scope="module")
def inputs(tmp_path_factory):
    manifest, records = owned_inputs(tmp_path_factory.mktemp("fixture-transfer-source"))
    corpus = prepare_fixture_training_corpus(manifest, records)
    tokenizer = train_fixture_tokenizer(corpus, policy=TOKENIZER)
    source = train_fixture_objectives(
        corpus, tokenizer, encoder_policy=ENCODER, training_policy=TRAINING
    )
    splits = authored_transfer_splits()
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    return corpus, source, splits, examples


def train(inputs, **updates):
    corpus, source, splits, examples = inputs
    values = {
        "fixture_corpus": corpus,
        "head_policy": HeadPolicy(classes=("telnet_enabled",), embedding_size=8, max_examples=128),
        "training_policy": FineTunePolicy(epochs=2),
        "loss_weights": LossWeights(severity=0),
    }
    values.update(updates)
    return train_multitask(splits, source, examples, **values)


@pytest.fixture(scope="module")
def fitted(inputs):
    return train(inputs)


def target(inputs, part):
    return next(group for group in inputs[2].partitions if group.split is part).records[0]


def changed_fixture_corpus(corpus, row, case):
    """Authored adversarial audit inputs only; never an actual external consent record."""
    manifest, imported = corpus.manifest, list(corpus.imported)
    if case == "source":
        manifest = manifest.model_copy(
            update={"source": manifest.source.model_copy(update={"source_id": row.source_id})}
        )
        imported = [item.model_copy(update={"source_id": row.source_id}) for item in imported]
    elif case == "raw":
        imported[0] = imported[0].model_copy(update={"raw_sha256": row.raw_sha256})
        manifest = manifest.model_copy(
            update={
                "records": (
                    manifest.records[0].model_copy(update={"expected_sha256": row.raw_sha256}),
                    *manifest.records[1:],
                )
            }
        )
    else:
        text = row.sanitized_text
        if case == "normalized":
            text = "! authored comment\n\n" + text
        elif case == "template":
            text = text.replace("255.255.255.0", "255.255.255.128")
        elif case == "near":
            text += "ip ssh version 1\n"
        imported[0] = imported[0].model_copy(
            update={
                "sanitized_text": text,
                "sanitized_sha256": digest(text),
                "vendor_hint": row.vendor_hint,
                "sanitization_version": row.sanitization_version,
            }
        )
        manifest = manifest.model_copy(
            update={
                "records": (
                    manifest.records[0].model_copy(update={"vendor_hint": row.vendor_hint}),
                    *manifest.records[1:],
                )
            }
        )
    return prepare_fixture_training_corpus(manifest, tuple(imported), policy=corpus.audit.policy)


def test_actual_fixture_encoder_is_used_without_manufactured_validation(inputs, fitted, tmp_path):
    corpus, source, splits, examples = inputs
    identity = pretraining_identity(source)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    mode = tuple(module.training for module in source.model.modules())
    gradients = tuple(parameter.requires_grad for parameter in source.model.parameters())
    repeated = train(inputs)
    assert isinstance(fitted.report, MultiTaskFixtureTransferReport)
    assert fitted.report.version == "multitask-training-0.3.0"
    assert fitted.report == repeated.report
    assert all(
        torch.equal(value, repeated.heads.state_dict()[name])
        for name, value in fitted.heads.state_dict().items()
    )
    assert pretraining_identity(source) == identity
    assert mode == tuple(module.training for module in source.model.modules())
    assert gradients == tuple(parameter.requires_grad for parameter in source.model.parameters())
    assert torch.equal(rng, torch.get_rng_state()) and threads == torch.get_num_threads()
    assert not any(parameter.requires_grad for parameter in fitted.pretrained.model.parameters())
    assert fitted.report.parameter_count == source.report.parameter_count + (
        fitted.report.trainable_parameters
    )
    assert source.report.validation_fingerprint is None
    assert source.report.losses[0].validation_total is None
    assert fitted.report.pretraining.exposure.physical_pretraining_isolation_proven is False
    assert fitted.report.pretraining.exposure.source_intake_count == len(corpus.imported)
    prediction = predict_multitask(fitted, examples[0].record)
    assert prediction.severity_scores is None and not prediction.calibrated
    assert prediction.embedding is not None and len(prediction.embedding) == 8
    assert not prediction.production_quality_proven
    batch = build_multitask_validation(fitted, splits, examples, fixture_corpus=corpus)
    metrics = evaluate(batch)
    assert batch.protocol.model_version == fitted.report.version
    assert metrics.cohorts["real_confirmed"].summary is None and not metrics.independent_test
    bundle = tmp_path / "fixture-transfer"
    save_multitask(fitted, bundle)
    restored = load_multitask(bundle)
    assert restored.report == fitted.report
    assert restored.pretrained.report.version == "config-fixture-pretraining-0.1.0"
    assert multitask_identity(restored) == multitask_identity(fitted)
    assert predict_multitask(restored, examples[0].record) == prediction
    assert torch.equal(rng, torch.get_rng_state()) and threads == torch.get_num_threads()


def test_content_only_nested_features_preserve_current_file_alignment(inputs):
    _, source, _, examples = inputs
    row = examples[0].record
    features = extract_aligned_features(row, source, max_windows=1000)
    altered = extract_aligned_features(
        row.model_copy(update={"site_id": "different", "device_role": "different"}),
        source,
        max_windows=1000,
    )
    assert features.blocks.shape[1] == features.lines.shape[1] == ENCODER.hidden_size
    assert features.line_numbers == tuple(sorted(set(features.line_numbers)))
    assert features.total_lines == len(row.sanitized_text.splitlines())
    assert torch.equal(features.blocks, altered.blocks) and torch.equal(
        features.lines, altered.lines
    )
    with pytest.raises(ValueError, match="budget"):
        extract_aligned_features(row, source, max_windows=0)


@pytest.mark.parametrize("part", [DatasetSplit.VALIDATION, DatasetSplit.TEST])
@pytest.mark.parametrize("case", ["source", "raw", "sanitized", "normalized", "template", "near"])
def test_every_heldout_overlap_method_refuses_whole_corpus(inputs, part, case):
    corpus, _, splits, _ = inputs
    row = target(inputs, part)
    changed = changed_fixture_corpus(corpus, row, case)
    if case in ("normalized", "template", "near"):
        upstream = _prepare_record(changed.imported[0], corpus.audit.policy.deduplication)
        downstream = _prepare_record(row, corpus.audit.policy.deduplication)
        assert upstream.fingerprint.sanitized_sha256 != downstream.fingerprint.sanitized_sha256
        if case == "near":
            assert upstream.fingerprint.template_sha256 != downstream.fingerprint.template_sha256
            assert _jaccard_similarity(upstream.tokens, downstream.tokens) >= 0.82
        else:
            attribute = case + "_sha256"
            assert getattr(upstream.fingerprint, attribute) == getattr(
                downstream.fingerprint, attribute
            )
    with pytest.raises(ValueError, match="heldout"):
        audit_fixture_exposure(changed, splits, (), policy=FixtureTransferPolicy())


@pytest.mark.parametrize("case", ["raw", "sanitized", "normalized", "template", "near"])
def test_train_overlap_is_counted_not_promoted_to_independent_isolation(inputs, case):
    corpus, _, splits, _ = inputs
    row = target(inputs, DatasetSplit.TRAIN)
    # The original generic authored templates recur in heldout. A distinct train-only
    # derived example exercises permitted train overlap, not a convenient heldout subset.
    text = row.sanitized_text + "ip ssh version 1\nno ip routing\nlogging console errors\n"
    derived = row.model_copy(update={"sanitized_text": text, "sanitized_sha256": digest(text)})
    changed = changed_fixture_corpus(corpus, derived, case)
    exposure = audit_fixture_exposure(changed, splits, (derived,), policy=FixtureTransferPolicy())
    assert exposure.train_overlap_counts[case] >= 1
    assert exposure.heldout_overlap_count == 0
    assert not exposure.physical_pretraining_isolation_proven


def test_same_content_members_do_not_hide_another_raw_source_overlap(inputs):
    corpus, _, splits, _ = inputs
    validation = target(inputs, DatasetSplit.VALIDATION)
    other_raw = validation.model_copy(update={"raw_sha256": corpus.imported[0].raw_sha256})
    with pytest.raises(ValueError, match="heldout"):
        audit_fixture_exposure(corpus, splits, (other_raw,), policy=FixtureTransferPolicy())
    train_row = target(inputs, DatasetSplit.TRAIN)
    train_raw = train_row.model_copy(update={"raw_sha256": corpus.imported[0].raw_sha256})
    before = audit_fixture_exposure(corpus, splits, (), policy=FixtureTransferPolicy())
    after = audit_fixture_exposure(corpus, splits, (train_raw,), policy=FixtureTransferPolicy())
    assert after.comparisons == before.comparisons and after.train_overlap_counts["raw"] == 1
    assert after.downstream_content_sha256 != before.downstream_content_sha256


def test_audit_covers_duplicate_and_structurally_held_source_members(tmp_path, inputs):
    manifest, records = owned_inputs(tmp_path, duplicate=True, malformed=True)
    corpus = prepare_fixture_training_corpus(
        manifest, records, policy=FixtureTrainingPolicy(structural_refusals="exclude")
    )
    exposure = audit_fixture_exposure(corpus, inputs[2], (), policy=FixtureTransferPolicy())
    assert exposure.source_intake_count == 5 and corpus.audit.training_count == 3
    assert exposure.comparisons == 5 * exposure.downstream_unique_content_count


def test_budget_fails_without_target_subsetting_and_false_proof_is_rejected(inputs):
    corpus, _, splits, _ = inputs
    with pytest.raises(ValueError, match="no subset/truncation"):
        audit_fixture_exposure(corpus, splits, (), policy=FixtureTransferPolicy(max_comparisons=1))
    exposure = audit_fixture_exposure(corpus, splits, (), policy=FixtureTransferPolicy())
    with pytest.raises(ValidationError, match="overstates"):
        FixtureExposureAudit.model_validate(
            exposure.model_dump() | {"physical_pretraining_isolation_proven": True}
        )


@pytest.mark.parametrize("case", ["absent", "test", "unsafe", "hash", "cross_partition"])
def test_downstream_inputs_are_revalidated_before_any_audit(inputs, case):
    corpus, _, splits, _ = inputs
    row = target(inputs, DatasetSplit.TRAIN)
    updates = {
        "absent": {"record_id": "not-present"},
        "test": target(inputs, DatasetSplit.TEST).model_dump(),
        "unsafe": {"sanitized_text": "hostname bad\npassword exposed\n"},
        "hash": {"sanitized_sha256": "f" * 64},
        "cross_partition": {
            "sanitized_text": target(inputs, DatasetSplit.VALIDATION).sanitized_text,
            "sanitized_sha256": target(inputs, DatasetSplit.VALIDATION).sanitized_sha256,
        },
    }
    altered = row.model_copy(update=updates[case])
    if case == "unsafe":
        altered = altered.model_copy(update={"sanitized_sha256": digest(altered.sanitized_text)})
    with pytest.raises(ValueError):
        audit_fixture_exposure(corpus, splits, (altered,), policy=FixtureTransferPolicy())


@pytest.mark.parametrize("case", ["fingerprint", "counts", "tokenizer", "nan", "dtype"])
def test_actual_source_report_targets_and_tensors_are_revalidated(inputs, case):
    corpus, source, splits, examples = inputs
    altered = copy.deepcopy(source)
    if case == "nan":
        with torch.no_grad():
            altered.model.projection.bias[0] = float("nan")
    elif case == "dtype":
        altered.model.double()
    elif case == "tokenizer":
        altered.tokenizer = altered.tokenizer.model_copy(update={"training_fingerprint": "f" * 64})
    elif case == "counts":
        altered.report = altered.report.model_copy(
            update={"train_counts": altered.report.train_counts | {"token": 1}}
        )
    else:
        altered.report = altered.report.model_copy(update={"train_fingerprint": "f" * 64})
    rng = torch.get_rng_state().clone()
    with pytest.raises(ValueError):
        validate_fixture_source(corpus, altered, splits, tuple(row.record for row in examples))
    assert torch.equal(rng, torch.get_rng_state())


def test_retained_corpus_is_required_at_fit_and_evaluation(inputs, fitted):
    _, _, splits, examples = inputs
    with pytest.raises(ValueError, match="retained private corpus"):
        train(inputs, fixture_corpus=None)
    with pytest.raises(ValueError, match="retained private corpus"):
        build_multitask_validation(fitted, splits, examples)
    from ml.training.pretraining_smoke import pretraining_fixtures

    with pytest.raises(ValueError, match="no semantic labels"):
        train(inputs, semantic_pairs=pretraining_fixtures()[1])


def test_manually_training_nested_encoder_is_refused(inputs):
    _, source, _, examples = inputs
    altered = copy.deepcopy(source)
    altered.model.encoder.train()
    assert not altered.model.training
    with pytest.raises(ValueError, match="evaluation mode"):
        extract_aligned_features(examples[0].record, altered, max_windows=1000)


@pytest.mark.parametrize("case", ["model", "report", "corpus", "version", "auxiliary"])
def test_bundle_bindings_fail_even_after_recomputing_heads_checksum(fitted, tmp_path, case):
    bundle = tmp_path / case
    save_multitask(fitted, bundle)
    payload = json.loads((bundle / "heads.json").read_text())
    if case == "version":
        payload["report"]["version"] = "multitask-training-0.2.0"
    elif case == "auxiliary":
        from ml.training.checkpoint import _file_hash

        state = torch.load(bundle / "encoder/weights.pt", weights_only=True)
        state["projection.bias"][0] += 1
        torch.save(state, bundle / "encoder/weights.pt")
        manifest = json.loads((bundle / "encoder/manifest.json").read_text())
        manifest["files"]["weights.pt"] = _file_hash(bundle / "encoder/weights.pt")
        (bundle / "encoder/manifest.json").write_text(json.dumps(manifest))
    else:
        field = {
            "model": "pretraining_sha256",
            "report": "report_sha256",
            "corpus": "corpus_sha256",
        }
        payload["report"]["pretraining"][field[case]] = "f" * 64
    text = json.dumps(payload)
    (bundle / "heads.json").write_text(text)
    (bundle / "heads.sha256").write_text(digest(text))
    with pytest.raises(ValueError):
        load_multitask(bundle)


def test_drift_invalidates_prediction_evaluation_and_registry_admission(inputs, fitted, tmp_path):
    corpus, _, splits, examples = inputs
    drift = copy.deepcopy(fitted)
    with torch.no_grad():
        drift.pretrained.model.projection.bias[0] += 1
    with pytest.raises(ValueError, match="binding"):
        predict_multitask(drift, examples[0].record)
    with pytest.raises(ValueError, match="binding"):
        build_multitask_validation(drift, splits, examples, fixture_corpus=corpus)
    registry = tmp_path / "registry"
    initialize_registry(registry)
    before = (registry / "registry.json").read_bytes()
    with pytest.raises(ValueError, match="offline-only"):
        register_model(registry, fitted, expected_identity=multitask_identity(fitted))
    assert sorted(path.name for path in registry.iterdir()) == ["registry.json"]
    assert (registry / "registry.json").read_bytes() == before


def test_full_cli_scenario_uses_retained_source_and_round_trips(inputs, tmp_path):
    corpus, source, _, _ = inputs
    bundle = tmp_path / "source"
    save_pretraining(source, bundle)
    manifest, records = tmp_path / "manifest.json", tmp_path / "records.json"
    manifest.write_text(corpus.manifest.model_dump_json())
    records.write_text(json.dumps([row.model_dump(mode="json") for row in corpus.imported]))
    output = tmp_path / "run"
    result = run_fixture_transfer(
        bundle, pretraining_identity(source), manifest, records, output, epochs=2
    )
    assert result["round_trip_predictions_equal"] and result["source_unchanged"]
    assert not result["independent_test"] and result["real_confirmed_quality"] is None
    assert not (output / ".incomplete").exists()
    with pytest.raises(FileExistsError):
        run_fixture_transfer(
            bundle, pretraining_identity(source), manifest, records, output, epochs=2
        )
    missing_output = tmp_path / "invalid-pin"
    with pytest.raises(ValueError, match="pin differs"):
        run_fixture_transfer(bundle, "f" * 64, manifest, records, missing_output, epochs=2)
    assert not missing_output.exists()


def test_changed_supervised_annotations_and_test_labels_cannot_enter_transfer(inputs):
    corpus, source, splits, examples = inputs
    first = examples[0]
    changed = (replace(first, parent_sha256="f" * 64), *examples[1:])
    with pytest.raises(ValueError):
        train((corpus, source, splits, changed))
    test_row = target(inputs, DatasetSplit.TEST)
    changed = (
        replace(first, record=test_row, parent_sha256=test_row.sanitized_sha256),
        *examples[1:],
    )
    with pytest.raises(ValueError):
        train((corpus, source, splits, changed))


def test_all_five_heads_require_declared_synthetic_severity_not_fixture_metadata(inputs):
    corpus, source, splits, examples = inputs
    declared = tuple(
        replace(
            row,
            annotation=row.annotation.model_copy(
                update={"severity": "high" if row.annotation.anomaly else None}
            ),
        )
        for row in examples
    )
    result = train((corpus, source, splits, declared), loss_weights=LossWeights())
    assert all(value > 0 for value in result.report.supervised_counts.values())
    assert predict_multitask(result, examples[0].record).severity_scores is not None
    assert source.report.corpus.confirmed_anomaly_count is None


@pytest.mark.parametrize("argument", ["fixture_corpus", "fixture_policy"])
def test_old_objective_transfer_cannot_silently_ignore_fixture_inputs(inputs, argument):
    from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
    from ml.training.pretraining import PretrainingPolicy
    from ml.training.pretraining_smoke import pretraining_fixtures

    splits, _ = pretraining_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=64)
    )
    source = train_configuration_objectives(
        splits, tokenizer, encoder_policy=ENCODER, training_policy=PretrainingPolicy(epochs=1)
    )
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    value = inputs[0] if argument == "fixture_corpus" else FixtureTransferPolicy()
    with pytest.raises(ValueError, match="cannot silently ignore"):
        train_multitask(
            splits,
            source,
            examples,
            head_policy=HeadPolicy(classes=("telnet_enabled",)),
            **{argument: value},
        )


@pytest.mark.parametrize("case", ["inventory", "permission"])
def test_changed_retained_intake_cannot_match_the_trained_model(inputs, case):
    corpus, source, splits, _ = inputs
    if case == "inventory":
        changed = replace(corpus, imported=corpus.imported[:-1])
    else:
        changed = replace(
            corpus,
            manifest=corpus.manifest.model_copy(
                update={"source": corpus.manifest.source.model_copy(update={"allowed_uses": []})}
            ),
        )
    with pytest.raises(ValueError):
        validate_fixture_source(changed, source, splits, ())


def test_fitting_budget_failure_keeps_original_weights_modes_and_process_state(inputs):
    source = inputs[1]
    before = pretraining_identity(source)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    modes = tuple(module.training for module in source.model.modules())
    with pytest.raises(ValueError, match="budget"):
        train(inputs, training_policy=FineTunePolicy(epochs=2, max_feature_values=1024))
    assert pretraining_identity(source) == before
    assert tuple(module.training for module in source.model.modules()) == modes
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads


def test_cli_failure_does_not_echo_private_paths_or_create_output(tmp_path, monkeypatch, capsys):
    from ml.training.fixture_transfer_smoke import main

    secret_path = tmp_path / "private-source-do-not-echo"
    output = tmp_path / "no-output"
    monkeypatch.setattr(
        "sys.argv",
        [
            "transfer",
            "--source-model",
            str(secret_path),
            "--source-sha256",
            "f" * 64,
            "--manifest",
            str(secret_path),
            "--records",
            str(secret_path),
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit) as failure:
        main()
    assert failure.value.code == 1
    diagnostic = capsys.readouterr().err
    assert (
        "Fixture transfer failed" in diagnostic and "private-source-do-not-echo" not in diagnostic
    )
    assert not output.exists()
