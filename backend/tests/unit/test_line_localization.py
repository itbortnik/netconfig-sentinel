"""Current-file line labels, frozen training, isolation, and safe persistence."""

import json
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
    stable_line_input,
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
    policy = LinePolicy(epochs=4, feature_version="stable-lines-0.1.0")
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
    for prefix, text in (
        (2, "\n\n" + row.record.sanitized_text),
        (0, row.record.sanitized_text.replace("\n", "\r\n")),
        (2, "\r\n \t\r\n" + row.record.sanitized_text.replace("\n", "\r\n")),
    ):
        altered = row.record.model_copy(
            update={"sanitized_text": text, "sanitized_sha256": digest(text)}
        )
        scores = predict_lines(first, altered)
        assert all(
            item.changed_score is None and item.predicted_changed is None
            for item in scores[:prefix]
        )
        assert [item.changed_score for item in scores[prefix:]] == [
            item.changed_score for item in predictions
        ]
        assert [item.line_number for item in scores[prefix:]] == [
            item.line_number + prefix for item in predictions
        ]
        assert all(item.source_sha256 == digest(text) for item in scores)
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
    legacy_path = tmp_path / "legacy-localizer"
    save_localizer(first, legacy_path)
    payload = json.loads((legacy_path / "localizer.json").read_text(encoding="utf-8"))
    del payload["report"]["policy"]["feature_version"]
    legacy_text = json.dumps(payload)
    (legacy_path / "localizer.json").write_text(legacy_text, encoding="utf-8")
    (legacy_path / "localizer.sha256").write_text(digest(legacy_text), encoding="ascii")
    legacy = load_localizer(legacy_path)
    assert legacy.report.policy.feature_version == "raw-lines-0.1.0"
    assert predict_lines(legacy, row.record) == predictions
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


def test_stable_input_preserves_internal_whitespace_and_legacy_policy() -> None:
    record = classification_fixtures().partitions[0].records[0]
    text = "\r\n \t\r\nhostname host-000000000001\r\n\r\nbanner motd ^\r\n\r\n hello\r\n^"
    source = record.model_copy(update={"sanitized_text": text, "sanitized_sha256": digest(text)})
    normalized, mapping = stable_line_input(source)
    assert normalized.sanitized_text == "hostname host-000000000001\n\nbanner motd ^\n\n hello\n^"
    assert mapping == (3, 4, 5, 6, 7, 8)
    assert source.sanitized_text == text
    assert LinePolicy.model_validate({}).feature_version == "raw-lines-0.1.0"
    with pytest.raises(ValueError, match="hash mismatch"):
        stable_line_input(source.model_copy(update={"sanitized_sha256": "0" * 64}))
