"""Train-only reference contexts retain parent provenance and fixed loss weighting."""

from pathlib import Path

import pytest
import torch

from ml.datasets import DatasetSplit
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification import prepare_examples
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import (
    LinePolicy,
    augment_reference_contexts,
    load_localizer,
    save_localizer,
    train_line_localizer,
)
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

TYPES = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)


def test_reference_variants_keep_commands_parents_and_bounds() -> None:
    splits = classification_fixtures()
    policy = LinePolicy(reference_augmentation="management-comments-0.1.0")
    rows, _ = prepare_examples(splits, TYPES, policy)
    originals = rows[DatasetSplit.TRAIN]
    augmented = augment_reference_contexts(originals, policy)
    assert augmented[: len(originals)] == originals
    references = {row.parent_sha256: row for row in originals if not row.label}
    assert len(augmented) == len(originals) + 3 * len(references)
    for row in augmented[len(originals) :]:
        parent = references[row.parent_sha256]
        assert row.label == 0 and row.mutation_id is None
        assert row.record.sanitized_text.endswith(parent.record.sanitized_text)
        prefix = row.record.sanitized_text[: -len(parent.record.sanitized_text)]
        assert all(line.startswith(("! ", "# ")) for line in prefix.splitlines())
        assert row.record.device_id == parent.record.device_id
        assert row.record.network_id == parent.record.network_id
        assert row.record.sanitized_sha256 == digest(row.record.sanitized_text)
    assert augmented == augment_reference_contexts(originals, policy)
    with pytest.raises(ValueError, match="example budget"):
        augment_reference_contexts(
            originals, policy.model_copy(update={"max_examples": len(originals)})
        )


def test_augmented_training_preserves_validation_and_positive_weight(tmp_path: Path) -> None:
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
    baseline_policy = LinePolicy(epochs=2, feature_version="stable-lines-0.1.0")
    baseline = train_line_localizer(splits, pretrained, TYPES, policy=baseline_policy)
    augmented = train_line_localizer(
        splits,
        pretrained,
        TYPES,
        policy=baseline_policy.model_copy(
            update={"reference_augmentation": "management-comments-0.1.0"}
        ),
    )
    assert augmented.report.augmented_reference_examples == 18
    assert augmented.report.train_lines > baseline.report.train_lines
    assert augmented.report.train_positive_lines == baseline.report.train_positive_lines
    assert augmented.report.positive_weight == baseline.report.positive_weight
    assert augmented.report.weight_reference_lines == baseline.report.train_lines
    assert augmented.report.validation_lines == baseline.report.validation_lines
    assert augmented.report.validation_fingerprint == baseline.report.validation_fingerprint
    assert augmented.report.train_fingerprint == baseline.report.train_fingerprint
    assert (
        augmented.report.effective_train_fingerprint != baseline.report.effective_train_fingerprint
    )
    assert all(
        torch.equal(value, baseline.pretrained.model.state_dict()[key])
        for key, value in augmented.pretrained.model.state_dict().items()
    )
    path = tmp_path / "augmented"
    save_localizer(augmented, path)
    restored = load_localizer(path)
    assert restored.report == augmented.report
    with pytest.raises(ValueError, match="provenance"):
        type(augmented.report).model_validate(
            {**augmented.report.model_dump(), "effective_train_fingerprint": None}
        )
