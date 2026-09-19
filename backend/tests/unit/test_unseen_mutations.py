"""Novel mutation families never enter fitting or the held-out test partition."""

from ml.datasets import DatasetSplit, deduplicate_dataset, split_deduplicated_dataset
from ml.datasets.laboratory import laboratory_records
from ml.preprocessing.blocks import digest
from ml.training.unseen_mutations import (
    KNOWN_TYPES,
    UNSEEN_TYPES,
    evaluate_unseen_mutations,
    unseen_examples,
)


def test_unseen_examples_preserve_partition_and_disjoint_label_families() -> None:
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    rows, skipped = unseen_examples(splits)
    assert set(KNOWN_TYPES).isdisjoint(UNSEEN_TYPES)
    assert DatasetSplit.TEST not in rows
    assert skipped
    for partition in splits.partitions:
        if partition.split is DatasetSplit.TEST:
            continue
        parents = {record.sanitized_sha256 for record in partition.records}
        for row in rows[partition.split]:
            assert row.parent_sha256 in parents
            if row.label:
                assert UNSEEN_TYPES[row.label - 1] not in KNOWN_TYPES
                assert row.mutation_id is not None


def test_report_separates_familiar_parents_and_does_not_evaluate_test() -> None:
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    first = evaluate_unseen_mutations(splits)
    changed = splits.model_copy(
        update={
            "partitions": tuple(
                partition.model_copy(
                    update={
                        "records": tuple(
                            record.model_copy(
                                update={
                                    "sanitized_text": "not a configuration",
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
    assert first == evaluate_unseen_mutations(changed)
    reports = first["unseen_by_parent_partition"]
    assert isinstance(reports, dict)
    assert reports["train"]["familiar_parent_configurations"] is True
    assert reports["validation"]["familiar_parent_configurations"] is False
    assert "validation_fingerprint" not in reports["train"]
    assert reports["train"]["model_sha256"] == reports["validation"]["model_sha256"]
    assert reports["train"]["by_variant"]["original"]["excluded_deletion_only"] > 0
    assert first["test_evaluated"] is False
