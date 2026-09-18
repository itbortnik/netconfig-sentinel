"""Tests for deterministic exact and near-duplicate dataset handling."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from app.domain import Vendor
from pydantic import ValidationError

from ml.datasets import (
    DatasetRecordReference,
    DeduplicationMethod,
    DeduplicationPolicy,
    ImportedDatasetRecord,
    deduplicate_dataset,
    normalize_configuration_text,
    template_configuration_text,
)

CAPTURED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record(
    record_id: str,
    text: str,
    *,
    raw_identity: str | None = None,
    source_id: str = "lab-source",
    network_id: str = "network-a",
    site_id: str = "site-a",
    device_id: str | None = None,
    captured_at: datetime = CAPTURED_AT,
) -> ImportedDatasetRecord:
    return ImportedDatasetRecord(
        source_id=source_id,
        record_id=record_id,
        network_id=network_id,
        site_id=site_id,
        device_id=device_id or record_id,
        captured_at=captured_at,
        vendor_hint=Vendor.CISCO,
        device_role="edge-router",
        raw_sha256=_sha256(raw_identity or f"raw:{record_id}:{text}"),
        sanitized_sha256=_sha256(text),
        sanitized_text=text,
        raw_byte_count=len(text.encode("utf-8")),
        replacements={},
        sanitization_version="config-sanitizer-0.1.0",
    )


def test_normalization_ignores_formatting_comments_and_case() -> None:
    first = """! generated comment
HOSTNAME host-aaaaaaaaaaaa
interface   GigabitEthernet0/1
 description UPLINK
"""
    second = """hostname host-aaaaaaaaaaaa

interface GigabitEthernet0/1
description uplink
"""

    assert normalize_configuration_text(first) == normalize_configuration_text(
        second
    )


def test_template_groups_abstract_topology_literals() -> None:
    first = """hostname host-aaaaaaaaaaaa
interface GigabitEthernet0/1
 ip address 10.10.1.1 255.255.255.0
router bgp 65001
 description "Primary uplink"
"""
    second = """hostname host-bbbbbbbbbbbb
interface GigabitEthernet0/22
 ip address 192.0.2.15 255.255.255.128
router bgp 64520
 description "Backup circuit"
"""

    assert template_configuration_text(first) == template_configuration_text(second)
    assert normalize_configuration_text(first) != normalize_configuration_text(second)


def test_raw_hash_has_highest_exact_match_priority() -> None:
    earlier = _record(
        "record-z",
        "hostname host-aaaaaaaaaaaa\n",
        raw_identity="identical original bytes",
        captured_at=CAPTURED_AT,
    )
    later = _record(
        "record-a",
        "hostname host-bbbbbbbbbbbb\n",
        raw_identity="identical original bytes",
        captured_at=CAPTURED_AT + timedelta(days=1),
    )

    result = deduplicate_dataset([later, earlier])

    assert result.input_count == 2
    assert result.unique_count == 1
    assert result.exact_duplicate_count == 1
    assert result.near_duplicate_count == 0
    assert result.unique_records == (earlier,)
    assert result.duplicate_clusters[0].links[0].method is DeduplicationMethod.RAW_SHA256
    assert result.duplicate_clusters[0].links[0].similarity == 1.0


def test_sanitized_hash_connects_different_raw_inputs() -> None:
    text = "hostname host-aaaaaaaaaaaa\ninterface Loopback0\n"
    first = _record("record-a", text, raw_identity="raw with secret one")
    second = _record("record-b", text, raw_identity="raw with secret two")

    result = deduplicate_dataset([first, second])

    link = result.duplicate_clusters[0].links[0]
    assert result.exact_duplicate_count == 1
    assert link.method is DeduplicationMethod.SANITIZED_SHA256


def test_normalized_hash_connects_formatting_variants() -> None:
    first = _record(
        "record-a",
        "hostname host-aaaaaaaaaaaa\n! separator\ninterface Loopback0\n",
    )
    second = _record(
        "record-b",
        "  HOSTNAME   host-aaaaaaaaaaaa\ninterface   Loopback0\n",
    )

    result = deduplicate_dataset([first, second])

    link = result.duplicate_clusters[0].links[0]
    assert result.exact_duplicate_count == 1
    assert link.method is DeduplicationMethod.NORMALIZED_SHA256


def test_verified_token_similarity_connects_near_duplicates() -> None:
    first = _record(
        "record-a",
        """hostname host-aaaaaaaaaaaa
interface GigabitEthernet0/1
 no shutdown
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
ip route 10.0.0.0 255.255.255.0 192.0.2.2
ntp server 192.0.2.10
logging host 192.0.2.20
""",
    )
    second = _record(
        "record-b",
        """hostname host-aaaaaaaaaaaa
interface GigabitEthernet0/1
 no shutdown
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
ip route 10.0.0.0 255.255.255.0 192.0.2.2
ntp server 192.0.2.10
logging host 192.0.2.21
""",
    )

    result = deduplicate_dataset(
        [first, second],
        policy=DeduplicationPolicy(near_duplicate_threshold=0.75),
    )

    link = result.duplicate_clusters[0].links[0]
    assert result.exact_duplicate_count == 0
    assert result.near_duplicate_count == 1
    assert link.method is DeduplicationMethod.MINHASH_TOKEN_SIMILARITY
    assert link.similarity == pytest.approx(13 / 17, abs=1e-6)


def test_template_similarity_alone_does_not_remove_records() -> None:
    first = _record(
        "record-a",
        """hostname host-aaaaaaaaaaaa
interface GigabitEthernet0/1
ip address 10.0.0.1 255.255.255.0
router bgp 65001
""",
        device_id="device-a",
    )
    second = _record(
        "record-b",
        """hostname host-bbbbbbbbbbbb
interface GigabitEthernet0/2
ip address 192.0.2.1 255.255.255.128
router bgp 64520
""",
        device_id="device-b",
    )

    result = deduplicate_dataset([first, second])

    assert result.unique_count == 2
    assert result.duplicate_clusters == ()
    assert result.template_group_count == 1
    assert len(result.template_groups) == 1
    assert result.template_groups[0].members == (
        DatasetRecordReference(source_id="lab-source", record_id="record-a"),
        DatasetRecordReference(source_id="lab-source", record_id="record-b"),
    )


def test_unrelated_records_remain_unique() -> None:
    first = _record("record-a", "hostname host-aaaaaaaaaaaa\nrouter bgp 65001\n")
    second = _record(
        "record-b",
        "set system services ssh\nset snmp community <redacted-community>\n",
    )

    result = deduplicate_dataset([first, second])

    assert result.unique_count == 2
    assert result.exact_duplicate_count == 0
    assert result.near_duplicate_count == 0


def test_large_shared_template_does_not_collapse_independent_records() -> None:
    records = [
        _record(
            f"record-{index:03d}",
            (
                f"hostname host-{index:012x}\n"
                f"interface GigabitEthernet0/{index}\n"
                f"ip address 10.0.{index}.1 255.255.255.0\n"
                f"router bgp {64512 + index}\n"
            ),
        )
        for index in range(1, 97)
    ]

    result = deduplicate_dataset(
        records,
        policy=DeduplicationPolicy(max_candidates_per_bucket=4),
    )

    assert result.input_count == 96
    assert result.unique_count == 96
    assert result.duplicate_clusters == ()
    assert len(result.template_groups) == 1
    assert len(result.template_groups[0].members) == 96


def test_result_is_independent_of_input_order() -> None:
    original = _record("record-a", "hostname host-aaaaaaaaaaaa\ninterface Loopback0\n")
    copy = _record(
        "record-b",
        " HOSTNAME host-aaaaaaaaaaaa\ninterface   Loopback0\n",
    )
    unrelated = _record("record-c", "set system services ssh\n")

    first = deduplicate_dataset([original, copy, unrelated])
    reordered = deduplicate_dataset([unrelated, copy, original])

    assert first == reordered


def test_duplicate_record_references_are_rejected() -> None:
    first = _record("record-a", "hostname host-aaaaaaaaaaaa\n")
    conflicting = _record("record-a", "hostname host-bbbbbbbbbbbb\n")

    with pytest.raises(ValueError, match="pairs must be unique"):
        deduplicate_dataset([first, conflicting])
    with pytest.raises(ValueError, match="at least one"):
        deduplicate_dataset([])


def test_policy_requires_even_lsh_partition() -> None:
    with pytest.raises(ValidationError, match="evenly divide"):
        DeduplicationPolicy(minhash_permutations=64, lsh_bands=7)
