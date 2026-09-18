"""Run a small local MLM training demonstration on explicitly synthetic fixtures."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.domain import Vendor

from ml.datasets import (
    DatasetSplitResult,
    ImportedDatasetRecord,
    deduplicate_dataset,
    split_deduplicated_dataset,
)
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.checkpoint import load_checkpoint, save_checkpoint
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model


def fixture_splits() -> DatasetSplitResult:
    """Nine tiny artificial topologies, exclusively for pipeline checks."""
    records = []
    for index in range(1, 10):
        vendor = Vendor.CISCO if index % 2 else Vendor.JUNIPER
        text = (
            f"hostname host-{index:012x}\ninterface GigabitEthernet0/{index}\n"
            f" ip address 198.51.{index}.1 255.255.255.0\nrouter bgp {64512 + index}\n"
            if vendor is Vendor.CISCO
            else f"set system host-name host-{index:012x}\n"
            f"set interfaces ge-0/0/{index} unit 0 family inet address 198.51.{index}.1/24\n"
            f"set routing-options autonomous-system {64512 + index}\n"
        )
        records.append(
            ImportedDatasetRecord(
                source_id="synthetic-smoke",
                record_id=f"record-{index}",
                network_id=f"network-{index}",
                site_id=f"site-{index}",
                device_id=f"device-{index}",
                captured_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=index),
                vendor_hint=vendor,
                device_role="edge-router",
                raw_sha256=digest(text),
                sanitized_sha256=digest(text),
                sanitized_text=text,
                raw_byte_count=len(text.encode()),
                replacements={},
                sanitization_version="config-sanitizer-0.1.0",
            )
        )
    return split_deduplicated_dataset(records, deduplicate_dataset(records))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new checkpoint directory")
    splits = fixture_splits()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=512, context_length=64)
    )
    result = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(),
        training_policy=TrainingPolicy(),
    )
    save_checkpoint(result, args.output)
    loaded = load_checkpoint(args.output)
    print("Synthetic fixture smoke run; not anomaly-detection evaluation.")
    print(loaded.report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
