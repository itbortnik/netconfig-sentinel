"""Unseen mutation-family diagnostics, with familiar and validation parents separated."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.datasets import (
    DatasetSplit,
    DatasetSplitResult,
    deduplicate_dataset,
    split_deduplicated_dataset,
)
from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationNotApplicableError, MutationType, mutate_configuration
from ml.preprocessing.tokenization import _validate_split_entities
from ml.training.classification import ProbeExample
from ml.training.lexical_localization import lexical_diagnostics, train_lexical_baseline

KNOWN_TYPES = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
UNSEEN_TYPES = tuple(item for item in MutationType if item not in KNOWN_TYPES)


def unseen_examples(
    splits: DatasetSplitResult,
) -> tuple[dict[DatasetSplit, list[ProbeExample]], dict[str, int]]:
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    _validate_split_entities(splits)
    hashes = {
        record.sanitized_sha256: partition.split
        for partition in splits.partitions
        for record in partition.records
    }
    partitions: dict[DatasetSplit, list[ProbeExample]] = {}
    skipped: dict[str, int] = {}
    for partition in splits.partitions:
        if partition.split is DatasetSplit.TEST:
            continue
        rows = []
        for record in sorted(partition.records, key=lambda item: (item.source_id, item.record_id)):
            rows.append(ProbeExample(record, 0, None, record.sanitized_sha256))
            if len(rows) > 1000:
                raise ValueError("unseen mutation example budget exceeded")
            for label, mutation in enumerate(UNSEEN_TYPES, 1):
                try:
                    sample = mutate_configuration(record, (mutation,), seed=17)
                except MutationNotApplicableError:
                    key = f"{partition.split}:{mutation}"
                    skipped[key] = skipped.get(key, 0) + 1
                    continue
                if hashes.setdefault(sample.mutated_sha256, partition.split) != partition.split:
                    raise ValueError("unseen mutation content crosses partitions")
                changed = record.model_copy(
                    update={
                        "sanitized_text": sample.mutated_text,
                        "sanitized_sha256": sample.mutated_sha256,
                    }
                )
                rows.append(
                    ProbeExample(changed, label, sample.mutation_id, record.sanitized_sha256)
                )
                if len(rows) > 1000:
                    raise ValueError("unseen mutation example budget exceeded")
        partitions[partition.split] = rows
    return partitions, skipped


def evaluate_unseen_mutations(splits: DatasetSplitResult) -> dict[str, object]:
    # Fit once on known classes. Novel examples are created only after fitting.
    model, known_validation = train_lexical_baseline(splits)
    partitions, skipped = unseen_examples(splits)
    reports = {}
    for split, rows in partitions.items():
        diagnostics = lexical_diagnostics(model, rows, UNSEEN_TYPES)
        # The generic diagnostic field must not claim train-parent rows are validation.
        diagnostics["evaluated_fingerprint"] = diagnostics.pop("validation_fingerprint")
        diagnostics["parent_partition"] = split.value
        diagnostics["familiar_parent_configurations"] = split is DatasetSplit.TRAIN
        reports[split.value] = diagnostics
    return {
        "version": "unseen-mutations-0.1.0",
        "synthetic_only": True,
        "test_evaluated": False,
        "independent_test": False,
        "threshold": 0.5,
        "training_mutation_types": [item.value for item in KNOWN_TYPES],
        "unseen_mutation_types": [item.value for item in UNSEEN_TYPES],
        "skipped_not_applicable": skipped,
        "known_validation": known_validation,
        "unseen_by_parent_partition": reports,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    report = evaluate_unseen_mutations(splits)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
    print(
        "Unseen-family development diagnostics; "
        "train-parent and validation-parent results are separate."
    )


if __name__ == "__main__":
    main()
