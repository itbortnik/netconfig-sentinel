"""MLM masking boundaries, CPU reproducibility, held-out isolation and checkpoints."""

from pathlib import Path

import pytest
import torch

from ml.datasets import DatasetSplit
from ml.preprocessing.blocks import digest, segment_configuration
from ml.preprocessing.tokenization import TokenizerPolicy, encode_block, train_config_tokenizer
from ml.training.checkpoint import load_checkpoint, save_checkpoint
from ml.training.masking import IGNORE_LABEL, mask_window
from ml.training.smoke import fixture_splits
from ml.training.transformer import (
    EncoderPolicy,
    TrainingPolicy,
    train_masked_language_model,
)


def test_masking_is_repeatable_and_excludes_padding_and_special_tokens() -> None:
    splits = fixture_splits()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=64)
    )
    block = segment_configuration(splits.partitions[0].records[0])[0]
    window = encode_block(block, tokenizer)[0]
    kwargs = {"vocab_size": tokenizer.actual_vocab_size, "seed": 17, "epoch": 1}
    first = mask_window(window, **kwargs)
    assert first == mask_window(window, **kwargs)
    assert any(label != IGNORE_LABEL for label in first.labels)
    for index, label in enumerate(first.labels):
        if not window.attention_mask[index] or window.special_tokens_mask[index]:
            assert label == IGNORE_LABEL
            assert first.input_ids[index] == window.input_ids[index]
        elif label != IGNORE_LABEL:
            assert label == window.input_ids[index]
    assert len({mask_window(window, **{**kwargs, "epoch": epoch}) for epoch in range(10)}) > 1


def test_cpu_training_reproducibility_test_isolation_and_checkpoint(tmp_path: Path) -> None:
    splits = fixture_splits()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=32)
    )
    encoder = EncoderPolicy(hidden_size=16, layers=1, heads=2, feedforward_size=32, dropout=0.1)
    policy = TrainingPolicy(epochs=2, batch_size=8, learning_rate=0.003)
    rng_before = torch.get_rng_state().clone()
    threads_before = torch.get_num_threads()
    first = train_masked_language_model(
        splits, tokenizer, encoder_policy=encoder, training_policy=policy
    )
    assert torch.equal(torch.get_rng_state(), rng_before)
    assert torch.get_num_threads() == threads_before
    # Hold-out content is deliberately malformed: training must never parse it.
    changed = tuple(
        partition.model_copy(
            update={
                "records": tuple(
                    item.model_copy(
                        update={
                            "sanitized_text": "not a configuration",
                            "sanitized_sha256": digest("holdout" + item.record_id),
                        }
                    )
                    for item in partition.records
                )
            }
        )
        if partition.split is DatasetSplit.TEST
        else partition
        for partition in splits.partitions
    )
    second = train_masked_language_model(
        splits.model_copy(update={"partitions": changed}),
        tokenizer,
        encoder_policy=encoder,
        training_policy=policy,
    )
    assert first.report == second.report
    assert first.report.test_evaluated is False
    assert all(
        torch.equal(value, second.model.state_dict()[key])
        for key, value in first.model.state_dict().items()
    )
    assert first.report.metrics[-1].train_loss < first.report.metrics[0].train_loss
    path = tmp_path / "model"
    save_checkpoint(first, path)
    restored = load_checkpoint(path)
    assert restored.report == first.report
    assert all(
        torch.equal(value, restored.model.state_dict()[key])
        for key, value in first.model.state_dict().items()
    )
    with pytest.raises(FileExistsError):
        save_checkpoint(first, path)
    with (path / "weights.pt").open("ab") as target:
        target.write(b"tampered")
    with pytest.raises(ValueError, match="checksum"):
        load_checkpoint(path)


def test_training_rejects_wrong_tokenizer_and_budget_overflow() -> None:
    splits = fixture_splits()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=32)
    )
    with pytest.raises(ValueError, match="different training corpus"):
        train_masked_language_model(
            splits, tokenizer.model_copy(update={"training_fingerprint": "0" * 64})
        )
    with pytest.raises(ValueError, match="budget exceeded"):
        train_masked_language_model(
            splits, tokenizer, training_policy=TrainingPolicy(max_windows=1)
        )
    with pytest.raises(ValueError, match="divisible"):
        EncoderPolicy(hidden_size=17, heads=2)
