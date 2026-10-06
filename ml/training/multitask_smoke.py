"""Authored injection labels and paired benign formatting views, not real severity."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path

from ml.datasets import DatasetSplitResult
from ml.evaluation.metrics import canonical_hash
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification import ProbePolicy, prepare_examples
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import line_targets
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_training import (
    FineTunePolicy,
    SupervisedAnnotation,
    SupervisedExample,
    predict_multitask,
    save_multitask,
    train_multitask,
)
from ml.training.transformer import train_masked_language_model


def authored_supervision(
    splits: DatasetSplitResult,
    types: tuple[MutationType, ...],
) -> tuple[SupervisedExample, ...]:
    """Two views per parent/mutation; partitions remain attached to original parent.

    No severity is inferred from injected operation or policy severity. Similarity
    labels mean the same synthetic recipe, not verified semantic equivalence.
    """
    rows, _ = prepare_examples(splits, types, ProbePolicy())
    examples = []
    for group in rows.values():
        parents = {row.parent_sha256: row.record.sanitized_text for row in group if row.label == 0}
        for row in group:
            target = line_targets(parents[row.parent_sha256], row.record.sanitized_text)
            targets = tuple(int(row.label == index) for index in range(1, len(types) + 1))
            annotation = SupervisedAnnotation(
                source_sha256=row.record.sanitized_sha256,
                annotation_sha256=canonical_hash(
                    ("owned-injection-label-0.1.0", row.mutation_id, row.parent_sha256, row.label)
                ),
                origin="synthetic",
                source_review_sha256=canonical_hash(
                    (
                        "owned repository classification fixtures",
                        "authored local fixtures; no third-party license asserted",
                        "synthetic-evaluation-and-training",
                    )
                ),
                target_semantics="injected_mutation",
                anomaly=bool(row.label),
                category_targets=targets,
                positive_lines=target.changed_lines,
                ignored_lines=target.ignored_lines,
                localization_reviewed=True,
                deletion_only=bool(row.label and not target.changed_lines),
                similarity_group=types[row.label - 1].value
                if row.label
                else "unmodified_reference",
            )
            example = SupervisedExample(row.record, row.parent_sha256, annotation)
            examples.append(example)
            text = "\n" + row.record.sanitized_text
            record = row.record.model_copy(
                update={"sanitized_text": text, "sanitized_sha256": digest(text)}
            )
            view = annotation.model_copy(
                update={
                    "source_sha256": record.sanitized_sha256,
                    "annotation_sha256": canonical_hash(
                        (annotation.annotation_sha256, "leading-blank-view-1")
                    ),
                    "positive_lines": tuple(line + 1 for line in annotation.positive_lines),
                    "ignored_lines": tuple(line + 1 for line in annotation.ignored_lines),
                }
            )
            examples.append(replace(example, record=record, annotation=view))
    return tuple(examples)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("choose a new output directory")
    splits = classification_fixtures()
    types = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=512, context_length=64)
    )
    encoder = train_masked_language_model(splits, tokenizer)
    result = train_multitask(
        splits,
        encoder,
        authored_supervision(splits, types),
        head_policy=HeadPolicy(classes=tuple(item.value for item in types)),
        training_policy=FineTunePolicy(),
        loss_weights=LossWeights(severity=0),
    )
    save_multitask(result, args.output)
    print(result.report.model_dump_json(indent=2))
    example = authored_supervision(splits, types)[0]
    print(predict_multitask(result, example.record).model_dump_json(indent=2))
    print(
        "Synthetic smoke only; severity disabled, paired views not independent cases, "
        "test untouched."
    )


if __name__ == "__main__":
    main()
