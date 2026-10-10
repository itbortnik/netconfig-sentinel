"""Real fixture-only optimization, provenance refusal and unchanged split boundaries."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import torch
from pydantic import ValidationError

from ml.datasets import (
    DatasetFixtureManifest,
    DatasetUse,
    import_local_dataset,
)
from ml.datasets.fixture_training import (
    FixtureTrainingPolicy,
    prepare_fixture_training_corpus,
    validate_fixture_training_corpus,
)
from ml.preprocessing import SanitizationPolicy
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_fixture_tokenizer
from ml.training.fixture_pretraining_cli import FixturePretrainingProtocol, run_fixture_pretraining
from ml.training.pretraining import (
    FixturePretrainingReport,
    ObjectiveEncoder,
    PretrainingPolicy,
    load_fixture_pretraining,
    load_pretraining,
    pretraining_identity,
    save_pretraining,
    train_fixture_objectives,
)
from ml.training.pretraining_data import TASKS, PretrainingWeights, prepare_fixture_pretraining
from ml.training.transformer import EncoderPolicy

TEXTS = (
    (
        "cisco",
        "hostname owned-a\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n"
        "router bgp 64512\n neighbor 10.0.0.2 remote-as 64513\n",
    ),
    (
        "juniper",
        "set system host-name owned-b\nset interfaces ge-0/0/1 unit 0 family inet "
        "address 10.1.0.1/24\nset routing-options autonomous-system 64514\n",
    ),
    (
        "juniper",
        "system { services { ssh; } }\ninterfaces { ge-0/0/1 { unit 0 { "
        "family inet { address 10.2.0.1/24; } } } }\n",
    ),
)
ENCODER = EncoderPolicy(hidden_size=16, layers=1, heads=2, feedforward_size=32, dropout=0)
TRAINING = PretrainingPolicy(epochs=2, embedding_size=8, max_records=512)
TOKENIZER = TokenizerPolicy(vocab_size=300, context_length=64)


def owned_inputs(path: Path, *, duplicate=False, malformed=False):
    texts = list(TEXTS)
    if duplicate:
        texts.append(TEXTS[0])
    if malformed:
        texts.append(("juniper", "system {\n services { ssh; }\n"))
    for index, (_, text) in enumerate(texts):
        (path / f"entry-{index}.cfg").write_text(text, encoding="utf-8", newline="")
    manifest = DatasetFixtureManifest.model_validate(
        {
            "source": {
                "source_id": "owned-training-fixtures",
                "source_type": "batfish_test",
                "origin": "authored local configs, no external source",
                "license_id": "CC0-1.0",
                "license_review": "approved",
                "allowed_uses": ["research", "training"],
                "collected_at": datetime(2026, 10, 10, tzinfo=UTC),
            },
            "records": [
                {
                    "record_id": f"entry-{index}",
                    "relative_path": f"entry-{index}.cfg",
                    "expected_sha256": digest(text),
                    "vendor_hint": vendor,
                }
                for index, (vendor, text) in enumerate(texts)
            ],
        }
    )
    records = import_local_dataset(
        manifest,
        root=path,
        intended_use=DatasetUse.TRAINING,
        pseudonymization_key=b"owned-fixture-pretraining-test-key",
        sanitization_policy=SanitizationPolicy(version="config-sanitizer-0.3.0"),
    )
    return manifest, records


@pytest.fixture(scope="module")
def source_data(tmp_path_factory):
    manifest, records = owned_inputs(tmp_path_factory.mktemp("fixture-training"))
    corpus = prepare_fixture_training_corpus(manifest, records)
    tokenizer = train_fixture_tokenizer(corpus, policy=TOKENIZER)
    return corpus, tokenizer


@pytest.fixture(scope="module")
def trained(source_data):
    corpus, tokenizer = source_data
    return train_fixture_objectives(
        corpus, tokenizer, encoder_policy=ENCODER, training_policy=TRAINING
    )


def test_deduplicate_before_tokenization_and_keep_unknown_metadata(tmp_path):
    manifest, records = owned_inputs(tmp_path, duplicate=True)
    corpus = prepare_fixture_training_corpus(manifest, records)
    assert corpus.audit.input_count == 4 and corpus.audit.training_count == 3
    assert corpus.audit.partition == "train_only"
    assert corpus.audit.independent_network_count is None and corpus.audit.device_count is None
    assert corpus.audit.confirmed_anomaly_count is None and corpus.audit.capture_time_range is None
    assert not corpus.audit.heldout_isolation_verified
    assert all(row.device_id is None and row.captured_at is None for row in corpus.records)
    reversed_corpus = prepare_fixture_training_corpus(manifest, tuple(reversed(records)))
    assert reversed_corpus.audit == corpus.audit and reversed_corpus.records == corpus.records
    tokenizer = train_fixture_tokenizer(corpus, policy=TOKENIZER)
    assert tokenizer.training_record_count == 3
    assert tokenizer.training_fingerprint == corpus.audit.training_fingerprint


def test_structural_hold_requires_explicit_policy_and_preserves_inventory(tmp_path):
    manifest, records = owned_inputs(tmp_path, malformed=True)
    with pytest.raises(ValueError, match="structural"):
        prepare_fixture_training_corpus(manifest, records)
    corpus = prepare_fixture_training_corpus(
        manifest,
        records,
        policy=FixtureTrainingPolicy(structural_refusals="exclude"),
    )
    assert corpus.audit.unique_count == 4 and corpus.audit.training_count == 3
    assert len(corpus.audit.exclusions) == 1 and len(corpus.audit.input_fingerprints) == 4
    assert corpus.audit.exclusions[0].sanitized_sha256 == records[-1].sanitized_sha256
    assert all(row.record_id != records[-1].record_id for row in corpus.records)
    assert validate_fixture_training_corpus(corpus) == corpus


@pytest.mark.parametrize("case", ["vendor", "oversized", "empty"])
def test_exclusion_policy_cannot_hide_vendor_or_input_budget_errors(source_data, case):
    corpus, _ = source_data
    manifest, records = corpus.manifest, list(corpus.imported)
    if case == "vendor":
        # The reviewed inventory agrees with the hint, but content contradicts it.
        manifest = manifest.model_copy(
            update={
                "records": (
                    manifest.records[0].model_copy(update={"vendor_hint": "juniper"}),
                    *manifest.records[1:],
                )
            }
        )
        records[0] = records[0].model_copy(update={"vendor_hint": "juniper"})
    else:
        text = "hostname owned-large\n" + "!" * (1024 * 1024) if case == "oversized" else ""
        records[0] = records[0].model_copy(
            update={
                "sanitized_text": text,
                "sanitized_sha256": digest(text),
            }
        )
    with pytest.raises(ValueError, match=r"vendor|bounded"):
        prepare_fixture_training_corpus(
            manifest,
            tuple(records),
            policy=FixtureTrainingPolicy(structural_refusals="exclude"),
        )


@pytest.mark.parametrize(
    "case",
    ["pending", "no_training", "source", "time", "raw", "vendor", "groups", "missing", "budget"],
)
def test_source_permission_manifest_inventory_and_group_refusals(source_data, case):
    corpus, _ = source_data
    manifest, records, policy = corpus.manifest, list(corpus.imported), None
    if case in ("pending", "no_training"):
        updates = (
            {"license_review": "pending"}
            if case == "pending"
            else {"allowed_uses": frozenset({DatasetUse.RESEARCH})}
        )
        manifest = manifest.model_copy(
            update={"source": manifest.source.model_copy(update=updates)}
        )
    elif case in ("source", "time", "raw", "vendor", "groups"):
        updates = {
            "source": {"source_id": "other-source"},
            "time": {"source_collected_at": records[0].source_collected_at + timedelta(days=1)},
            "raw": {"raw_sha256": "f" * 64},
            "vendor": {"vendor_hint": None},
            "groups": {"collection_group_id": "collection-000000000000"},
        }[case]
        records[0] = records[0].model_copy(update=updates)
    elif case == "missing":
        records.pop()
    else:
        policy = FixtureTrainingPolicy(max_records=1)
    with pytest.raises(ValueError):
        prepare_fixture_training_corpus(manifest, tuple(records), policy=policy)


@pytest.mark.parametrize("field", ["device_id", "captured_at", "network_id", "site_id"])
def test_model_copy_cannot_manufacture_entity_metadata(source_data, field):
    corpus, _ = source_data
    changed = corpus.imported[0].model_copy(update={field: "invented"})
    with pytest.raises(ValueError, match="schema"):
        prepare_fixture_training_corpus(corpus.manifest, (changed, *corpus.imported[1:]))


@pytest.mark.parametrize("case", ["content_hash", "secret", "selection", "audit"])
def test_corrupted_corpus_never_reaches_bpe_or_objectives(source_data, case):
    corpus, _ = source_data
    if case in ("content_hash", "secret"):
        row = corpus.imported[0].model_copy(update={"sanitized_text": "enable secret owned-test\n"})
        if case == "secret":
            row = row.model_copy(update={"sanitized_sha256": digest(row.sanitized_text)})
        corpus = replace(corpus, imported=(row, *corpus.imported[1:]))
    elif case == "selection":
        corpus = replace(corpus, records=corpus.records[:-1])
    else:
        corpus = replace(corpus, audit=corpus.audit.model_copy(update={"block_count": 1}))
    with pytest.raises(ValueError):
        train_fixture_tokenizer(corpus, policy=TOKENIZER)


def test_objective_data_uses_shared_masks_and_no_device_semantic_labels(source_data):
    corpus, tokenizer = source_data
    data = prepare_fixture_pretraining(corpus, tokenizer)
    assert data.records == 3 and data.windows > 0
    assert all(data.counts()[name] > 0 for name in TASKS[:3])
    assert all(data.counts()[name] == 0 for name in TASKS[3:])
    assert not data.semantic_scopes and not data.same_device and not data.cross_vendor
    assert not data.replaced_line
    assert data.source_fingerprint == tokenizer.training_fingerprint
    assert data == prepare_fixture_pretraining(corpus, tokenizer)


@pytest.mark.parametrize("budget", ["max_records", "max_windows", "max_examples"])
def test_objective_bounds_do_not_silently_truncate(source_data, budget):
    corpus, tokenizer = source_data
    with pytest.raises(ValueError, match="budget"):
        prepare_fixture_pretraining(corpus, tokenizer, **{budget: 1})


@pytest.mark.parametrize(
    "field", ["training_fingerprint", "training_record_count", "training_block_count"]
)
def test_tokenizer_training_binding_is_rechecked(source_data, field):
    corpus, tokenizer = source_data
    value = "f" * 64 if field == "training_fingerprint" else 999
    with pytest.raises(ValueError, match="different"):
        prepare_fixture_pretraining(corpus, tokenizer.model_copy(update={field: value}))


@pytest.mark.parametrize("task", TASKS[3:])
def test_identity_or_semantic_objectives_cannot_be_enabled(source_data, task):
    corpus, tokenizer = source_data
    weights = PretrainingWeights(replaced_line=0, same_device=0, cross_vendor=0)
    with pytest.raises(ValueError, match="labels"):
        train_fixture_objectives(corpus, tokenizer, weights=weights.model_copy(update={task: 1}))


def test_actual_training_updates_only_encoder_and_restores_rng(source_data, trained):
    corpus, tokenizer = source_data
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    second = train_fixture_objectives(
        corpus, tokenizer, encoder_policy=ENCODER, training_policy=TRAINING
    )
    assert pretraining_identity(second) == pretraining_identity(trained)
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert torch.are_deterministic_algorithms_enabled() == deterministic
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(TRAINING.seed)
        initial = ObjectiveEncoder(tokenizer, ENCODER, TRAINING)
    changed = []
    for name, value in trained.model.state_dict().items():
        assert torch.isfinite(value).all()
        if name.startswith("encoder."):
            changed.append(not torch.equal(value, initial.state_dict()[name]))
        else:
            assert torch.equal(value, initial.state_dict()[name])
    assert any(changed)
    report = trained.report
    assert report.selection == "fixed_final_epoch" and report.selected_epoch == 2
    assert report.validation_counts is None and report.validation_fingerprint is None
    assert all(row.validation_total is None for row in report.losses)
    assert all(row.train_components[name] is None for row in report.losses for name in TASKS[3:])
    assert not report.test_evaluated and not report.production_quality_proven
    assert not trained.model.training


def test_train_only_never_runs_validation_or_selects_minimum_loss(source_data, monkeypatch):
    from ml.training import pretraining

    corpus, tokenizer = source_data
    original, calls = pretraining._run_objectives, []

    def recorded(model, data, policy, weights, *, backward):
        calls.append(backward)
        components, total = original(model, data, policy, weights, backward=backward)
        # Deliberately worsen reported losses; final epoch still selected, no min-train selection.
        if len(calls) == 2:
            components = {
                name: None if value is None else value + 100 for name, value in components.items()
            }
            total = sum(
                getattr(weights, name) * value
                for name, value in components.items()
                if value is not None
            )
        return components, total

    monkeypatch.setattr(pretraining, "_run_objectives", recorded)
    result = train_fixture_objectives(
        corpus, tokenizer, encoder_policy=ENCODER, training_policy=TRAINING
    )
    assert calls == [True, True] and result.report.selected_epoch == 2
    assert result.report.losses[-1].train_total > result.report.losses[0].train_total


def test_failure_restores_rng_threads_deterministic_state(source_data, monkeypatch):
    from ml.training import pretraining

    corpus, tokenizer = source_data
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()

    def fail(*args, **kwargs):
        raise ValueError("owned controlled training failure")

    monkeypatch.setattr(pretraining, "_run_objectives", fail)
    with pytest.raises(ValueError, match="controlled"):
        train_fixture_objectives(
            corpus, tokenizer, encoder_policy=ENCODER, training_policy=TRAINING
        )
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert torch.are_deterministic_algorithms_enabled() == deterministic


def test_bundle_round_trip_explicit_loader_and_no_legacy_transfer(trained, tmp_path):
    from ml.training.pretraining_transfer import validate_objective_model

    bundle = tmp_path / "bundle"
    save_pretraining(trained, bundle)
    rng = torch.get_rng_state().clone()
    restored = load_fixture_pretraining(bundle)
    assert torch.equal(rng, torch.get_rng_state())
    assert restored.report == trained.report
    assert pretraining_identity(restored) == pretraining_identity(trained)
    with pytest.raises(ValueError):
        load_pretraining(bundle)
    with pytest.raises(ValueError):
        validate_objective_model(restored)
    with pytest.raises(FileExistsError):
        save_pretraining(trained, bundle)


@pytest.mark.parametrize(
    "case",
    [
        "validation",
        "selection",
        "protocol",
        "total",
        "counts",
        "identity",
        "exposure",
        "nonfinite",
        "inventory",
    ],
)
def test_recomputed_checksums_do_not_relax_report_or_weight_contract(trained, tmp_path, case):
    from ml.training.checkpoint import _file_hash

    bundle = tmp_path / "bundle"
    save_pretraining(trained, bundle)
    if case == "nonfinite":
        state = torch.load(bundle / "weights.pt", weights_only=True)
        state["encoder.head.bias"][0] = float("nan")
        torch.save(state, bundle / "weights.pt")
    elif case == "inventory":
        (bundle / ".incomplete").touch()
    else:
        report = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
        if case == "validation":
            report["losses"][0]["validation_total"] = 0
        elif case == "selection":
            report["selected_epoch"] = 1
        elif case == "protocol":
            report["protocol_sha256"] = "f" * 64
        elif case == "total":
            report["losses"][0]["train_total"] += 1
        elif case == "counts":
            report["train_counts"]["token"] = 0
        elif case == "identity":
            report["weights"]["same_device"] = 1
        else:
            report["corpus"]["training_count"] += 1
        (bundle / "report.json").write_text(json.dumps(report), encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"] = {name: _file_hash(bundle / name) for name in manifest["files"]}
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        load_fixture_pretraining(bundle)


def test_report_revalidation_refuses_missing_loss_or_false_quality(trained):
    with pytest.raises(ValidationError):
        FixturePretrainingReport.model_validate(
            trained.report.model_copy(update={"production_quality_proven": True}).model_dump()
        )


def test_cli_end_to_end_freezes_protocol_and_verifies_saved_weights(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest, records = owned_inputs(inputs, malformed=True)
    manifest_path, records_path, protocol_path = (
        inputs / "manifest.json",
        inputs / "records.json",
        inputs / "protocol.json",
    )
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    records_path.write_text(
        json.dumps([row.model_dump(mode="json") for row in records]), encoding="utf-8"
    )
    protocol = FixturePretrainingProtocol(
        corpus=FixtureTrainingPolicy(structural_refusals="exclude"),
        tokenizer=TOKENIZER,
        encoder=ENCODER,
        training=TRAINING,
    )
    protocol_path.write_text(protocol.model_dump_json(), encoding="utf-8")
    output = tmp_path / "experiment"
    result = run_fixture_pretraining(manifest_path, records_path, protocol_path, output)
    assert result["training_count"] == 3 and result["structural_hold_count"] == 1
    assert result["bundle_round_trip_verified"] and result["validation_metrics"] is None
    assert not (output / ".incomplete").exists()
    assert result["model_identity"] == pretraining_identity(
        load_fixture_pretraining(output / "bundle")
    )
    with pytest.raises(FileExistsError):
        run_fixture_pretraining(manifest_path, records_path, protocol_path, output)


@pytest.mark.parametrize("case", ["duplicate_json", "bad_rows", "unapproved", "unsupported"])
def test_cli_invalid_inputs_leave_no_output(tmp_path, case):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest, records = owned_inputs(inputs)
    manifest_path, records_path, protocol_path = (
        inputs / "manifest.json",
        inputs / "records.json",
        inputs / "protocol.json",
    )
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    records_path.write_text(
        json.dumps([row.model_dump(mode="json") for row in records]), encoding="utf-8"
    )
    protocol = FixturePretrainingProtocol(encoder=ENCODER, tokenizer=TOKENIZER, training=TRAINING)
    if case == "unapproved":
        manifest_path.write_text(
            manifest.model_copy(
                update={
                    "source": manifest.source.model_copy(update={"license_review": "pending"}),
                }
            ).model_dump_json(warnings=False),
            encoding="utf-8",
        )
    elif case == "bad_rows":
        records_path.write_text("{}", encoding="utf-8")
    elif case == "unsupported":
        protocol = protocol.model_copy(update={"weights": PretrainingWeights(same_device=1)})
    protocol_path.write_text(protocol.model_dump_json(), encoding="utf-8")
    if case == "duplicate_json":
        protocol_path.write_text('{"training":{},"training":{}}', encoding="utf-8")
    output = tmp_path / "must-not-exist"
    with pytest.raises(ValueError):
        run_fixture_pretraining(manifest_path, records_path, protocol_path, output)
    assert not output.exists()
