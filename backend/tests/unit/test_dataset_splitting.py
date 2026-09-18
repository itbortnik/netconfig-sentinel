"""Tests for entity-isolated chronological dataset partitioning."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from app.domain import Vendor
from pydantic import ValidationError

from ml.datasets import (
    DatasetSplit,
    DatasetSplitPolicy,
    DatasetSplitResult,
    ImportedDatasetRecord,
    deduplicate_dataset,
    split_deduplicated_dataset,
)

CAPTURED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record(
    index: int,
    *,
    day: int,
    network_id: str | None = None,
    site_id: str | None = None,
    device_id: str | None = None,
    text: str | None = None,
    raw_identity: str | None = None,
) -> ImportedDatasetRecord:
    sanitized_text = text or (
        f"hostname host-{index:012x}\n"
        f"interface GigabitEthernet0/{index}\n"
        f"ip address 10.0.{index}.1 255.255.255.0\n"
        f"router bgp {64512 + index}\n"
    )
    return ImportedDatasetRecord(
        source_id="lab-source",
        record_id=f"record-{index:03d}",
        network_id=network_id or f"network-{index:03d}",
        site_id=site_id or f"site-{index:03d}",
        device_id=device_id or f"device-{index:03d}",
        captured_at=CAPTURED_AT + timedelta(days=day),
        vendor_hint=Vendor.CISCO,
        device_role="edge-router",
        raw_sha256=_sha256(raw_identity or f"raw-{index}"),
        sanitized_sha256=_sha256(sanitized_text),
        sanitized_text=sanitized_text,
        raw_byte_count=len(sanitized_text.encode("utf-8")),
        replacements={},
        sanitization_version="config-sanitizer-0.1.0",
    )


def _assignment_map(result: DatasetSplitResult) -> dict[str, DatasetSplit]:
    assignments = result.assignments
    return {
        assignment.record.record_id: assignment.split for assignment in assignments
    }


def test_chronological_split_matches_targets_for_equal_groups() -> None:
    records = [_record(index, day=index) for index in range(1, 11)]
    deduplication = deduplicate_dataset(records)

    result = split_deduplicated_dataset(
        records,
        deduplication,
        policy=DatasetSplitPolicy(
            train_fraction=0.6,
            validation_fraction=0.2,
            test_fraction=0.2,
        ),
    )

    partitions = {partition.split: partition for partition in result.partitions}
    assert len(partitions[DatasetSplit.TRAIN].records) == 6
    assert len(partitions[DatasetSplit.VALIDATION].records) == 2
    assert len(partitions[DatasetSplit.TEST].records) == 2
    assert partitions[DatasetSplit.TRAIN].actual_fraction == 0.6
    assert partitions[DatasetSplit.VALIDATION].actual_fraction == 0.2
    assert partitions[DatasetSplit.TEST].actual_fraction == 0.2
    assert result.temporal_audit.strict_order is True
    assert result.cross_split_template_count == 1
    assert result.template_audit[0].splits == frozenset(DatasetSplit)


def test_network_site_device_and_duplicate_clusters_are_indivisible() -> None:
    records = [
        _record(
            1,
            day=1,
            network_id="network-a",
            site_id="site-a",
            device_id="device-a",
        ),
        _record(
            2,
            day=2,
            network_id="network-a",
            site_id="site-a",
            device_id="device-a",
        ),
        _record(3, day=3, raw_identity="shared-original"),
        _record(4, day=4, raw_identity="shared-original"),
        _record(5, day=5),
        _record(6, day=6),
    ]
    deduplication = deduplicate_dataset(records)

    result = split_deduplicated_dataset(
        records,
        deduplication,
        policy=DatasetSplitPolicy(
            train_fraction=0.5,
            validation_fraction=0.25,
            test_fraction=0.25,
        ),
    )

    assignments = _assignment_map(result)
    assert assignments["record-001"] is assignments["record-002"]
    assert assignments["record-003"] is assignments["record-004"]
    duplicate_assignments = [
        assignment
        for assignment in result.assignments
        if assignment.record.record_id in {"record-003", "record-004"}
    ]
    assert sum(item.is_representative for item in duplicate_assignments) == 1
    assert result.input_count == 6
    assert result.unique_count == 5


def test_all_test_entities_are_absent_from_training() -> None:
    records = [_record(index, day=index) for index in range(1, 13)]
    deduplication = deduplicate_dataset(records)
    result = split_deduplicated_dataset(records, deduplication)

    train = [item for item in result.assignments if item.split is DatasetSplit.TRAIN]
    test = [item for item in result.assignments if item.split is DatasetSplit.TEST]
    train_networks = {(item.record.source_id, item.network_id) for item in train}
    test_networks = {(item.record.source_id, item.network_id) for item in test}
    train_sites = {(item.record.source_id, item.site_id) for item in train}
    test_sites = {(item.record.source_id, item.site_id) for item in test}

    assert train_networks.isdisjoint(test_networks)
    assert train_sites.isdisjoint(test_sites)
    assert test_networks
    assert test_sites


def test_temporal_overlap_is_reported_or_rejected_in_strict_mode() -> None:
    records = [
        _record(
            1,
            day=1,
            network_id="long-network",
            site_id="long-site",
            device_id="long-device",
        ),
        _record(
            2,
            day=10,
            network_id="long-network",
            site_id="long-site",
            device_id="long-device",
        ),
        _record(3, day=2),
        _record(4, day=3),
        _record(5, day=4),
    ]
    deduplication = deduplicate_dataset(records)
    policy = DatasetSplitPolicy(
        train_fraction=0.4,
        validation_fraction=0.2,
        test_fraction=0.4,
    )

    result = split_deduplicated_dataset(records, deduplication, policy=policy)

    assert result.temporal_audit.strict_order is False
    assert any("overlap in capture time" in item for item in result.limitations)

    with pytest.raises(ValueError, match="strict temporal order"):
        split_deduplicated_dataset(
            records,
            deduplication,
            policy=policy.model_copy(update={"require_strict_temporal_order": True}),
        )


def test_split_is_independent_of_input_order() -> None:
    records = [_record(index, day=index) for index in range(1, 9)]
    deduplication = deduplicate_dataset(records)

    first = split_deduplicated_dataset(records, deduplication)
    reordered = split_deduplicated_dataset(list(reversed(records)), deduplication)

    assert first == reordered


def test_split_rejects_mismatched_deduplication_input() -> None:
    records = [_record(index, day=index) for index in range(1, 5)]
    deduplication = deduplicate_dataset(records)

    with pytest.raises(ValueError, match="exactly match"):
        split_deduplicated_dataset(records[:3], deduplication)

    changed = records[0].model_copy(update={"raw_sha256": "0" * 64})
    with pytest.raises(ValueError, match="hashes do not match"):
        split_deduplicated_dataset([changed, *records[1:]], deduplication)


def test_split_rejects_too_few_isolated_groups() -> None:
    records = [
        _record(
            index,
            day=index,
            network_id="one-network",
            site_id="one-site",
        )
        for index in range(1, 5)
    ]
    deduplication = deduplicate_dataset(records)

    with pytest.raises(ValueError, match="not enough isolated"):
        split_deduplicated_dataset(records, deduplication)


def test_split_policy_requires_complete_fractions() -> None:
    with pytest.raises(ValidationError, match="sum to 1"):
        DatasetSplitPolicy(
            train_fraction=0.7,
            validation_fraction=0.2,
            test_fraction=0.2,
        )
