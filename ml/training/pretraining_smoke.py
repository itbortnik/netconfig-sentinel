"""Exercise every pretraining objective on authored, narrowly scoped synthetic pairs."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.domain import Vendor

from ml.datasets import (
    DatasetSplit,
    DatasetSplitResult,
    ImportedDatasetRecord,
    deduplicate_dataset,
    split_deduplicated_dataset,
)
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.pretraining import (
    PretrainingPolicy,
    load_pretraining,
    save_pretraining,
    train_configuration_objectives,
)
from ml.training.pretraining_data import PretrainingWeights, SemanticPair
from ml.training.transformer import EncoderPolicy

SCOPE = "ipv4_static_route_destinations_and_next_hops"


def pretraining_fixtures() -> tuple[DatasetSplitResult, tuple[SemanticPair, ...]]:
    """Twelve authored paired topologies, not real data or full-config equivalence."""
    records = []
    for index in range(1, 13):
        for vendor in (Vendor.CISCO, Vendor.JUNIPER):
            text = (
                f"hostname host-{vendor.value}-{index}\n"
                "aaa new-model\nip ssh version 2\n"
                f"interface GigabitEthernet0/{index}\n"
                f" ip address 198.18.{index}.1 255.255.255.0\n"
                f"router bgp {64512 + index}\n"
                f" neighbor 198.18.{index}.2 remote-as {64513 + index}\n"
                f"ip route 203.0.113.{index} 255.255.255.255 198.18.{index}.2\n"
                if vendor is Vendor.CISCO
                else f"set system host-name host-{vendor.value}-{index}\n"
                "set system services ssh\n"
                f"set interfaces ge-0/0/{index} unit 0 family inet address 198.18.{index}.1/24\n"
                f"set routing-options autonomous-system {64512 + index}\n"
                f"set protocols bgp group upstream peer-as {64513 + index}\n"
                f"set protocols bgp group upstream neighbor 198.18.{index}.2\n"
                f"set routing-options static route 203.0.113.{index}/32 next-hop 198.18.{index}.2\n"
            )
            records.append(
                ImportedDatasetRecord(
                    source_id="synthetic-pretraining",
                    record_id=f"record-{index}-{vendor.value}",
                    network_id=f"network-{index}",
                    site_id=f"site-{index}",
                    device_id=f"device-{index}-{vendor.value}",
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
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    pairs = []
    for part in splits.partitions:
        if part.split is DatasetSplit.TEST:
            continue
        cisco = [row for row in part.records if row.vendor_hint is Vendor.CISCO]
        junos = [row for row in part.records if row.vendor_hint is Vendor.JUNIPER]
        for left in cisco:
            matching = next(row for row in junos if row.network_id == left.network_id)
            different = next(row for row in junos if row.network_id != left.network_id)
            for right, equivalent in ((matching, True), (different, False)):
                pairs.append(
                    SemanticPair(
                        left_sha256=left.sanitized_sha256,
                        right_sha256=right.sanitized_sha256,
                        equivalent=equivalent,
                        scope=SCOPE,
                        origin="synthetic",
                        review_sha256=canonical_hash(
                            {
                                "scope": SCOPE,
                                "left": left.sanitized_sha256,
                                "right": right.sanitized_sha256,
                                "equivalent": equivalent,
                                "source": "authored synthetic fixture; static route tuple only",
                                "license": "no third-party source or license asserted",
                                "excluded": "BGP, interfaces, management, defaults, reachability",
                            }
                        ),
                    )
                )
    return splits, tuple(pairs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=10)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("choose a new output directory")
    splits, pairs = pretraining_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=512, context_length=128)
    )
    result = train_configuration_objectives(
        splits,
        tokenizer,
        semantic_pairs=pairs,
        weights=PretrainingWeights(cross_vendor=0.1),
        encoder_policy=EncoderPolicy(hidden_size=32, heads=4, layers=2, feedforward_size=64),
        training_policy=PretrainingPolicy(epochs=args.epochs),
    )
    save_pretraining(result, args.output)
    restored = load_pretraining(args.output)
    print("Synthetic objective training only; no anomaly quality/full-config equivalence claim.")
    print(restored.report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
