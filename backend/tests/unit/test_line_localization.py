"""Current-file line labels, frozen training, isolation, and safe persistence."""

from pathlib import Path

import pytest
import torch

from ml.datasets import DatasetSplit
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification import ProbeExample, prepare_examples
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import (
    LinePolicy,
    _dataset_features,
    _line_features,
    line_targets,
    load_localizer,
    predict_lines,
    save_localizer,
    train_line_localizer,
)
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

TYPES = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)


@pytest.mark.parametrize(
    ("before", "after", "changed", "ignored", "deleted"),
    [
        ("a\nb\nc\n", "a\nx\nc\n", (2,), (), 0),
        ("a\nb\n", "a\nx\nb\n", (2,), (), 0),
        ("a\nb\nc\n", "a\nc\n", (), (1, 2), 1),
        ("a\nb\n", "b\n", (), (1,), 1),
        ("a\nb\n", "a\n", (), (1,), 1),
        ("a\r\nb\r\n", "a\r\nx\r\n", (2,), (), 0),
        ("a\nb", "a\nb", (), (), 0),
    ],
)
def test_targets_use_current_lines_not_deleted_anchors(
    before: str,
    after: str,
    changed: tuple[int, ...],
    ignored: tuple[int, ...],
    deleted: int,
) -> None:
    targets = line_targets(before, after)
    assert targets.changed_lines == changed
    assert targets.ignored_lines == ignored
    assert targets.deleted_lines == deleted


def test_training_frozen_repeatable_heldout_and_roundtrip(tmp_path: Path) -> None:
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=16)
    )
    pretrained = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    before = {key: value.clone() for key, value in pretrained.model.state_dict().items()}
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    policy = LinePolicy(epochs=4)
    first = train_line_localizer(splits, pretrained, TYPES, policy=policy)
    assert torch.equal(rng, torch.get_rng_state())
    assert torch.get_num_threads() == threads
    assert all(
        torch.equal(value, pretrained.model.state_dict()[key]) for key, value in before.items()
    )
    assert all(
        torch.equal(value, first.pretrained.model.state_dict()[key])
        for key, value in before.items()
    )
    assert all(
        not parameter.requires_grad and parameter.grad is None
        for parameter in first.pretrained.model.parameters()
    )
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
    second = train_line_localizer(changed, pretrained, TYPES, policy=policy)
    assert first.report == second.report
    assert all(
        torch.equal(value, second.head.state_dict()[key])
        for key, value in first.head.state_dict().items()
    )
    assert first.report.losses[-1][0] < first.report.losses[0][0]
    rows, _ = prepare_examples(splits, TYPES, policy)
    validation_rows = rows[DatasetSplit.VALIDATION]
    original = next(item for item in validation_rows if item.label == 0)
    deleted_text = "\n".join(original.record.sanitized_text.splitlines()[:-1]) + "\n"
    deleted_record = original.record.model_copy(
        update={
            "sanitized_text": deleted_text,
            "sanitized_sha256": digest(deleted_text),
        }
    )
    deletion_only = ProbeExample(deleted_record, 1, "deletion-test", original.parent_sha256)
    _, _, excluded = _dataset_features([*validation_rows, deletion_only], first.pretrained, policy)
    assert excluded == 1
    with pytest.raises(ValueError, match="positive and negative"):
        _dataset_features([original, deletion_only], first.pretrained, policy)
    row = next(row for row in rows[DatasetSplit.VALIDATION] if row.label)
    predictions = predict_lines(first, row.record)
    assert len(predictions) == len(row.record.sanitized_text.splitlines())
    assert [prediction.line_number for prediction in predictions] == list(
        range(1, len(predictions) + 1)
    )
    assert all(
        prediction.source_sha256 == row.record.sanitized_sha256 for prediction in predictions
    )
    features, included = _line_features(row.record, first.pretrained, policy, [0, 0])
    assert included.all()  # Includes source lines crossing several short token windows.
    assert torch.isfinite(features).all()
    path = tmp_path / "localizer"
    save_localizer(first, path)
    restored = load_localizer(path)
    assert restored.report == first.report
    assert predict_lines(restored, row.record) == predictions
    with pytest.raises(FileExistsError):
        save_localizer(first, path)
    for bounded_policy, error in (
        (LinePolicy(max_lines=1), "line budget"),
        (LinePolicy(max_windows=1), "window budget"),
    ):
        with pytest.raises(ValueError, match=error):
            train_line_localizer(splits, pretrained, TYPES, policy=bounded_policy)
        assert torch.equal(rng, torch.get_rng_state())
        assert torch.get_num_threads() == threads
    with pytest.raises(ValueError, match="class weight"):
        type(first.report).model_validate({**first.report.model_dump(), "positive_weight": 999})
    (path / "localizer.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        load_localizer(path)
