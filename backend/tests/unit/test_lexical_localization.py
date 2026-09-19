"""Lexical baseline repeatability, held-out isolation and coordinate preservation."""

import pytest
from app.domain import Vendor

from ml.datasets import DatasetSplit, deduplicate_dataset, split_deduplicated_dataset
from ml.datasets.laboratory import laboratory_records
from ml.preprocessing.blocks import digest
from ml.training.lexical_localization import predict_lexical_lines, train_lexical_baseline


def test_lexical_training_is_repeatable_and_excludes_validation_vocabulary() -> None:
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    first, report = train_lexical_baseline(splits)
    second, repeated = train_lexical_baseline(splits)
    assert report == repeated
    assert first.vocabulary_sha256 == second.vocabulary_sha256
    assert (
        first.pipeline.named_steps["classifier"].coef_
        == second.pipeline.named_steps["classifier"].coef_
    ).all()
    partitions = []
    for partition in splits.partitions:
        changed_records = []
        for record in partition.records:
            if partition.split is DatasetSplit.TRAIN:
                changed_records.append(record)
                continue
            if partition.split is DatasetSplit.TEST:
                text = "not parseable"
                checksum = digest(record.record_id)
            else:
                marker = "!" if record.vendor_hint is Vendor.CISCO else "#"
                text = f"{marker} validation-only ☃\n" + record.sanitized_text
                checksum = digest(text)
            changed_records.append(
                record.model_copy(update={"sanitized_text": text, "sanitized_sha256": checksum})
            )
        partitions.append(partition.model_copy(update={"records": tuple(changed_records)}))
    altered, _ = train_lexical_baseline(splits.model_copy(update={"partitions": tuple(partitions)}))
    assert altered.train_fingerprint == first.train_fingerprint
    assert altered.vocabulary_sha256 == first.vocabulary_sha256
    assert all("☃" not in token for token in altered.pipeline.named_steps["tfidf"].vocabulary_)
    assert (
        altered.pipeline.named_steps["tfidf"].idf_ == first.pipeline.named_steps["tfidf"].idf_
    ).all()
    assert (
        altered.pipeline.named_steps["classifier"].coef_
        == first.pipeline.named_steps["classifier"].coef_
    ).all()
    assert report["independent_test"] is False


def test_lexical_line_mapping_and_input_checks() -> None:
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    model, _ = train_lexical_baseline(splits)
    record = records[0]
    baseline = predict_lexical_lines(model, record)
    text = "\r\n\r\n" + record.sanitized_text.replace("\n", "\r\n")
    changed = record.model_copy(update={"sanitized_text": text, "sanitized_sha256": digest(text)})
    shifted = predict_lexical_lines(model, changed)
    assert all(item.changed_score is None for item in shifted[:2])
    assert [item.changed_score for item in shifted[2:]] == [item.changed_score for item in baseline]
    assert [item.line_number for item in shifted[2:]] == [item.line_number + 2 for item in baseline]
    assert all(item.source_sha256 == digest(text) for item in shifted)
    with pytest.raises(ValueError, match="checksum"):
        predict_lexical_lines(model, changed.model_copy(update={"sanitized_sha256": "0" * 64}))
    empty = record.model_copy(update={"sanitized_text": "", "sanitized_sha256": digest("")})
    with pytest.raises(ValueError, match="empty"):
        predict_lexical_lines(model, empty)
