"""Tests for honest dataset metrics and integrity-checked artifact storage."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.domain import Vendor

from ml.datasets import (
    DatasetSource,
    DatasetSourceType,
    DatasetUse,
    ImportedDatasetRecord,
    LicenseReviewStatus,
    QualityIssueSeverity,
    build_dataset_quality_report,
    deduplicate_dataset,
    load_dataset_artifact,
    split_deduplicated_dataset,
    write_dataset_artifact,
)

CAPTURED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source(
    *,
    review: LicenseReviewStatus = LicenseReviewStatus.APPROVED,
    allowed_uses: frozenset[DatasetUse] = frozenset({DatasetUse.TRAINING}),
) -> DatasetSource:
    return DatasetSource(
        source_id="lab-source",
        source_type=DatasetSourceType.LAB,
        origin="controlled isolated lab",
        license_id="CC0-1.0",
        license_url="https://creativecommons.org/publicdomain/zero/1.0/",
        license_review=review,
        allowed_uses=allowed_uses,
        collected_at=CAPTURED_AT,
    )


def _record(
    index: int,
    *,
    text: str | None = None,
    raw_identity: str | None = None,
) -> ImportedDatasetRecord:
    sanitized_text = text or (
        f"hostname host-{index:012x}\n"
        f"interface GigabitEthernet0/{index}\n"
        f" ip address 198.51.100.{index} 255.255.255.0\n"
        f"router bgp {64512 + index}\n"
    )
    return ImportedDatasetRecord(
        source_id="lab-source",
        record_id=f"record-{index:03d}",
        network_id=f"network-{index:03d}",
        site_id=f"site-{index:03d}",
        device_id=f"device-{index:03d}",
        captured_at=CAPTURED_AT + timedelta(days=index),
        vendor_hint=Vendor.CISCO,
        device_role="edge-router",
        raw_sha256=_sha256(raw_identity or f"raw-input-{index}"),
        sanitized_sha256=_sha256(sanitized_text),
        sanitized_text=sanitized_text,
        raw_byte_count=len(sanitized_text.encode("utf-8")),
        replacements={"hostname": 1, "ip_address": 1},
        sanitization_version="config-sanitizer-0.1.0",
    )


def test_quality_report_uses_actual_counts_and_separates_scale_readiness() -> None:
    records = [_record(index) for index in range(1, 7)]
    deduplication = deduplicate_dataset(records)
    split_result = split_deduplicated_dataset(records, deduplication)

    report = build_dataset_quality_report(
        records,
        deduplication,
        split_result,
        sources=[_source()],
        intended_use=DatasetUse.TRAINING,
        confirmed_anomaly_count=2,
    )

    assert report.technically_valid is True
    assert report.blocking_issue_count == 0
    assert report.poc_scale_ready is False
    assert report.metrics.candidate_configuration_count == 6
    assert report.metrics.unique_configuration_count == 6
    assert report.metrics.independent_network_count == 6
    assert report.metrics.confirmed_anomaly_count == 2
    assert report.metrics.unseen_test_network_fraction == 1.0
    assert report.metrics.unseen_test_site_fraction == 1.0
    assert report.metrics.configuration_block_count > 0
    assert report.metrics.token_count > 0
    assert report.sources[0].license_id == "CC0-1.0"
    assert all(target.actual < target.target_minimum for target in report.scale_targets)


def test_quality_report_is_independent_of_input_order() -> None:
    records = [_record(index) for index in range(1, 7)]
    deduplication = deduplicate_dataset(records)
    split_result = split_deduplicated_dataset(records, deduplication)

    first = build_dataset_quality_report(
        records,
        deduplication,
        split_result,
        sources=[_source()],
        intended_use=DatasetUse.TRAINING,
    )
    reordered = build_dataset_quality_report(
        list(reversed(records)),
        deduplication,
        split_result,
        sources=[_source()],
        intended_use=DatasetUse.TRAINING,
    )

    assert first == reordered


def test_quality_report_blocks_unreviewed_source_and_residual_secrets() -> None:
    unsafe_text = (
        "hostname production-edge\n"
        "username administrator secret cleartext-password\n"
        "snmp-server community public RO\n"
    )
    records = [_record(1, text=unsafe_text), _record(2), _record(3), _record(4)]
    deduplication = deduplicate_dataset(records)
    split_result = split_deduplicated_dataset(records, deduplication)

    report = build_dataset_quality_report(
        records,
        deduplication,
        split_result,
        sources=[_source(review=LicenseReviewStatus.PENDING)],
        intended_use=DatasetUse.TRAINING,
    )

    codes = {issue.code for issue in report.issues}
    assert report.technically_valid is False
    assert report.blocking_issue_count >= 4
    assert "source.review_not_approved" in codes
    assert "sanitization.hostname" in codes
    assert "sanitization.username" in codes
    assert "sanitization.secret_value" in codes
    assert "sanitization.snmp_community" in codes
    blocking_codes = {
        issue.code
        for issue in report.issues
        if issue.severity is QualityIssueSeverity.BLOCKING
    }
    assert {
        "source.review_not_approved",
        "sanitization.hostname",
        "sanitization.username",
        "sanitization.secret_value",
        "sanitization.snmp_community",
    } <= blocking_codes


def test_quality_report_blocks_unlicensed_use_and_hash_mismatch() -> None:
    records = [_record(index) for index in range(1, 5)]
    changed = records[0].model_copy(update={"sanitized_text": "hostname changed\n"})
    changed_records = [changed, *records[1:]]
    deduplication = deduplicate_dataset(changed_records)
    split_result = split_deduplicated_dataset(changed_records, deduplication)

    report = build_dataset_quality_report(
        changed_records,
        deduplication,
        split_result,
        sources=[_source(allowed_uses=frozenset({DatasetUse.RESEARCH}))],
        intended_use=DatasetUse.TRAINING,
    )

    codes = {issue.code for issue in report.issues}
    assert "source.use_not_permitted" in codes
    assert "integrity.sanitized_hash_mismatch" in codes
    assert report.technically_valid is False


def test_artifact_write_is_deterministic_non_overwriting_and_verifiable(
    tmp_path: Path,
) -> None:
    records = [
        _record(index, raw_identity=f"RAW-SECRET-MATERIAL-{index}")
        for index in range(1, 7)
    ]
    deduplication = deduplicate_dataset(records)
    split_result = split_deduplicated_dataset(records, deduplication)
    report = build_dataset_quality_report(
        records,
        deduplication,
        split_result,
        sources=[_source()],
        intended_use=DatasetUse.TRAINING,
    )

    first = write_dataset_artifact(
        records,
        deduplication,
        split_result,
        report,
        output_root=tmp_path,
        artifact_name="dataset-v1",
    )
    second = write_dataset_artifact(
        list(reversed(records)),
        deduplication,
        split_result,
        report,
        output_root=tmp_path,
        artifact_name="dataset-v1-copy",
    )

    assert first.manifest == load_dataset_artifact(first.path)
    assert first.manifest.artifact_id == second.manifest.artifact_id
    assert first.manifest.files == second.manifest.files
    assert not (first.path / ".incomplete").exists()
    assert len(first.manifest.files) == 6
    combined = b"".join(
        path.read_bytes() for path in first.path.rglob("*") if path.is_file()
    )
    assert b"RAW-SECRET-MATERIAL" not in combined
    dedup_audit = json.loads(
        (first.path / "audit" / "deduplication.json").read_text(encoding="utf-8")
    )
    split_audit = json.loads(
        (first.path / "audit" / "splitting.json").read_text(encoding="utf-8")
    )
    assert "unique_records" not in dedup_audit
    assert all("records" not in partition for partition in split_audit["partitions"])

    with pytest.raises(FileExistsError, match="will not be overwritten"):
        write_dataset_artifact(
            records,
            deduplication,
            split_result,
            report,
            output_root=tmp_path,
            artifact_name="dataset-v1",
        )


def test_artifact_loader_detects_tampering_and_incomplete_output(tmp_path: Path) -> None:
    records = [_record(index) for index in range(1, 7)]
    deduplication = deduplicate_dataset(records)
    split_result = split_deduplicated_dataset(records, deduplication)
    report = build_dataset_quality_report(
        records,
        deduplication,
        split_result,
        sources=[_source()],
        intended_use=DatasetUse.TRAINING,
    )
    written = write_dataset_artifact(
        records,
        deduplication,
        split_result,
        report,
        output_root=tmp_path,
        artifact_name="dataset-v1",
    )
    train_path = written.path / "records" / "train.jsonl"
    train_path.write_bytes(train_path.read_bytes() + b"{}\n")

    with pytest.raises(ValueError, match="integrity check failed"):
        load_dataset_artifact(written.path)

    incomplete = tmp_path / "incomplete"
    incomplete.mkdir()
    (incomplete / ".incomplete").write_text("incomplete\n", encoding="utf-8")
    with pytest.raises(ValueError, match="incomplete"):
        load_dataset_artifact(incomplete)


def test_artifact_writer_refuses_blocking_quality_report(tmp_path: Path) -> None:
    records = [_record(index) for index in range(1, 5)]
    deduplication = deduplicate_dataset(records)
    split_result = split_deduplicated_dataset(records, deduplication)
    report = build_dataset_quality_report(
        records,
        deduplication,
        split_result,
        sources=[_source(review=LicenseReviewStatus.REJECTED)],
        intended_use=DatasetUse.TRAINING,
    )

    with pytest.raises(ValueError, match="blocking quality issues"):
        write_dataset_artifact(
            records,
            deduplication,
            split_result,
            report,
            output_root=tmp_path,
            artifact_name="rejected",
        )
    assert not (tmp_path / "rejected").exists()
