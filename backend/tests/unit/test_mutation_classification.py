"""Synthetic probe isolation, frozen encoder, metrics, and persistence."""

from pathlib import Path

import pytest
import torch

from ml.datasets import DatasetSplit
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification import (
    ProbePolicy,
    _metrics,
    load_probe,
    predict_mutations,
    prepare_examples,
    save_probe,
    train_mutation_probe,
)
from ml.training.classification_smoke import classification_fixtures
from ml.training.transformer import (
    EncoderPolicy,
    TrainingPolicy,
    TrainingResult,
    train_masked_language_model,
)

TYPES = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)


def test_examples_inherit_parent_partition_and_budget() -> None:
    splits = classification_fixtures()
    rows, skipped = prepare_examples(splits, TYPES, ProbePolicy())
    assert not skipped
    assert DatasetSplit.TEST not in rows
    for partition in splits.partitions:
        if partition.split is DatasetSplit.TEST:
            continue
        assert len(rows[partition.split]) == 3 * len(partition.records)
        parents = {record.sanitized_sha256 for record in partition.records}
        for row in rows[partition.split]:
            assert row.parent_sha256 in parents
            assert bool(row.mutation_id) == bool(row.label)
            assert digest(row.record.sanitized_text) == row.record.sanitized_sha256
    with pytest.raises(ValueError, match="example budget"):
        prepare_examples(splits, TYPES, ProbePolicy(max_examples=1))
    with pytest.raises(ValueError, match="unique"):
        prepare_examples(splits, (TYPES[0], TYPES[0]), ProbePolicy())
    with pytest.raises(ValueError, match="training example"):
        prepare_examples(splits, (MutationType.MISSING_NTP_SYSLOG,), ProbePolicy())


def test_frozen_probe_repeatability_holdout_isolation_and_bundle(tmp_path: Path) -> None:
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=32)
    )
    pretrained = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    before = {key: value.clone() for key, value in pretrained.model.state_dict().items()}
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    policy = ProbePolicy(epochs=4)
    first = train_mutation_probe(splits, pretrained, TYPES, policy=policy)
    assert torch.equal(rng, torch.get_rng_state())
    assert threads == torch.get_num_threads()
    assert all(
        torch.equal(value, pretrained.model.state_dict()[key]) for key, value in before.items()
    )
    assert all(
        torch.equal(value, first.pretrained.model.state_dict()[key])
        for key, value in before.items()
    )
    assert all(parameter.grad is None for parameter in first.pretrained.model.parameters())
    assert not any(parameter.requires_grad for parameter in first.pretrained.model.parameters())
    changed = splits.model_copy(
        update={
            "partitions": tuple(
                partition.model_copy(
                    update={
                        "records": tuple(
                            record.model_copy(
                                update={
                                    "sanitized_text": "not parseable",
                                    "sanitized_sha256": digest(record.record_id),
                                }
                            )
                            for record in partition.records
                        )
                    }
                )
                if partition.split is DatasetSplit.TEST
                else partition
                for partition in splits.partitions
            )
        }
    )
    second = train_mutation_probe(changed, pretrained, TYPES, policy=policy)
    assert first.report == second.report
    assert all(
        torch.equal(value, second.head.state_dict()[key])
        for key, value in first.head.state_dict().items()
    )
    assert first.report.test_evaluated is False
    assert first.report.losses[-1][0] < first.report.losses[0][0]
    path = tmp_path / "probe"
    save_probe(first, path)
    restored = load_probe(path)
    record = splits.partitions[0].records[0]
    probabilities = predict_mutations(first, record)
    assert predict_mutations(restored, record) == probabilities
    assert sum(probabilities.values()) == pytest.approx(1)
    with pytest.raises(FileExistsError):
        save_probe(first, path)
    with pytest.raises(ValueError, match="window budget"):
        train_mutation_probe(splits, pretrained, TYPES, policy=ProbePolicy(max_windows=1))
    wrong_tokenizer = TrainingResult(
        pretrained.model,
        pretrained.tokenizer,
        pretrained.report.model_copy(update={"tokenizer_sha256": "0" * 64}),
    )
    with pytest.raises(ValueError, match="tokenizer does not match"):
        train_mutation_probe(splits, wrong_tokenizer, TYPES, policy=policy)
    wrong_corpus = TrainingResult(
        pretrained.model,
        pretrained.tokenizer,
        pretrained.report.model_copy(update={"training_fingerprint": "0" * 64}),
    )
    with pytest.raises(ValueError, match="different training corpus"):
        train_mutation_probe(splits, wrong_corpus, TYPES, policy=policy)
    assert torch.equal(rng, torch.get_rng_state())
    assert threads == torch.get_num_threads()
    (path / "classifier.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        load_probe(path)


def test_per_class_metrics_and_absent_class() -> None:
    metrics = _metrics(
        torch.tensor([[0.8, 0.2, 0.0], [0.6, 0.4, 0.0]]),
        torch.tensor([0, 1]),
        ("reference", "mutation", "absent"),
    )
    assert metrics[0].precision == 0.5
    assert metrics[0].recall == 1
    assert metrics[0].f1 == pytest.approx(2 / 3)
    assert metrics[1].average_precision == 1
    assert metrics[2].average_precision is None
    assert metrics[2].support == 0


def test_derived_hash_collision_with_heldout_is_rejected() -> None:
    splits = classification_fixtures()
    rows, _ = prepare_examples(splits, TYPES, ProbePolicy())
    injected_hash = next(
        row.record.sanitized_sha256 for row in rows[DatasetSplit.TRAIN] if row.label
    )
    changed = splits.model_copy(
        update={
            "partitions": tuple(
                partition.model_copy(
                    update={
                        "records": tuple(
                            record.model_copy(update={"sanitized_sha256": injected_hash})
                            if index == 0
                            else record
                            for index, record in enumerate(partition.records)
                        )
                    }
                )
                if partition.split is DatasetSplit.TEST
                else partition
                for partition in splits.partitions
            )
        }
    )
    with pytest.raises(ValueError, match="leaks across"):
        prepare_examples(changed, TYPES, ProbePolicy())
