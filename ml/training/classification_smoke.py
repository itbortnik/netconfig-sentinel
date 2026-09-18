"""Demonstrate a synthetic mutation classifier, not real anomaly quality."""

from __future__ import annotations

import argparse
from pathlib import Path

from app.domain import Vendor

from ml.datasets import DatasetSplitResult, deduplicate_dataset, split_deduplicated_dataset
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification import load_probe, save_probe, train_mutation_probe
from ml.training.smoke import fixture_splits
from ml.training.transformer import train_masked_language_model


def classification_fixtures() -> DatasetSplitResult:
    records = []
    for partition in fixture_splits().partitions:
        for record in partition.records:
            extra = (
                "aaa new-model\nline vty 0 4\n transport input ssh\n"
                if record.vendor_hint is Vendor.CISCO
                else "set system services ssh\n"
                "set system authentication-order [ radius password ]\n"
            )
            text = record.sanitized_text + extra
            records.append(
                record.model_copy(
                    update={
                        "sanitized_text": text,
                        "sanitized_sha256": digest(text),
                        "raw_sha256": digest(text),
                        "raw_byte_count": len(text.encode()),
                    }
                )
            )
    return split_deduplicated_dataset(records, deduplicate_dataset(records))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new directory")
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=512, context_length=64)
    )
    pretrained = train_masked_language_model(splits, tokenizer)
    result = train_mutation_probe(
        splits, pretrained, (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    )
    save_probe(result, args.output)
    restored = load_probe(args.output)
    print("Synthetic validation smoke only; no real/test anomaly evaluation or calibration.")
    print(restored.report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
