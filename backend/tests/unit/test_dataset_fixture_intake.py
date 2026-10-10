"""Owned fixture intake does not invent networks, device captures or labels."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.domain import Vendor
from app.parsers.coverage import parse_configuration_with_coverage
from pydantic import ValidationError

from ml.datasets import (
    DatasetDeduplicationResult,
    DatasetFixtureDeduplicationResult,
    DatasetFixtureManifest,
    DatasetFixtureRecord,
    DatasetSource,
    DatasetSourceType,
    DatasetUse,
    ImportedDatasetFixtureRecord,
    ImportedDatasetRecord,
    LicenseReviewStatus,
    build_dataset_quality_report,
    deduplicate_dataset,
    import_local_dataset,
    load_dataset_fixture_manifest,
    load_dataset_manifest,
    split_deduplicated_dataset,
    write_dataset_artifact,
)
from ml.mutation import MutationType, mutate_configuration
from ml.preprocessing import SanitizationPolicy
from ml.preprocessing.blocks import segment_configuration

ACQUIRED = datetime(2026, 10, 10, tzinfo=UTC)
KEY = b"owned-source-fixture-test-key"
TEXT = "hostname owned-router\nip prefix-list EDGE seq 5 permit 10.0.0.0/24 le 32\n"
POLICY = SanitizationPolicy(version="config-sanitizer-0.3.0")


def source(**updates: object) -> DatasetSource:
    return DatasetSource.model_validate({
        "source_id": "owned-upstream-fixtures", "source_type": "batfish_test",
        "origin": "authored local test source", "license_id": "CC0-1.0",
        "license_review": "approved", "allowed_uses": ["research", "training"],
        "collected_at": ACQUIRED, **updates,
    })


def manifest(text: str = TEXT, **updates: object) -> DatasetFixtureManifest:
    return DatasetFixtureManifest.model_validate({
        "source": source(), "records": [{
            "record_id": "owned-a", "relative_path": "owned.cfg",
            "expected_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "vendor_hint": "cisco", **updates,
        }],
    })


def imported(tmp_path: Path, text: str = TEXT) -> ImportedDatasetFixtureRecord:
    (tmp_path / "owned.cfg").write_text(text, encoding="utf-8", newline="")
    return import_local_dataset(
        manifest(text), root=tmp_path, intended_use=DatasetUse.TRAINING,
        pseudonymization_key=KEY, sanitization_policy=POLICY,
    )[0]


@pytest.mark.parametrize("field", [
    "network_id", "site_id", "device_id", "captured_at", "device_role",
])
@pytest.mark.parametrize("value", ["unknown", "fixture-001", "2026-10-10T00:00:00Z"])
def test_fixture_contract_rejects_invented_observation_metadata(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        manifest(**{field: value})


@pytest.mark.parametrize("field", ["ground_truth", "healthy", "anomaly_label", "unexpected"])
def test_fixture_contract_does_not_accept_labels(field: str) -> None:
    with pytest.raises(ValidationError):
        manifest(**{field: True})


@pytest.mark.parametrize("path", ["../a.cfg", "/a.cfg", "C:/a.cfg", "a\\b.cfg", "a//b.cfg"])
def test_fixture_paths_use_the_existing_boundary(path: str) -> None:
    with pytest.raises(ValidationError):
        manifest(relative_path=path)


@pytest.mark.parametrize("kind", [DatasetSourceType.LAB, DatasetSourceType.AUTHORIZED_REAL])
def test_fixture_contract_cannot_replace_real_or_lab_metadata(kind: DatasetSourceType) -> None:
    with pytest.raises(ValidationError, match="real or lab"):
        DatasetFixtureManifest(
            source=source(source_type=kind, authorization_reference="owned-authorization"),
            records=manifest().records,
        )


@pytest.mark.parametrize("field", ["record_id", "relative_path"])
def test_fixture_manifest_rejects_duplicate_references(field: str) -> None:
    first = manifest().records[0]
    changed = first.model_dump()
    changed.update(record_id="owned-b", relative_path="other.cfg")
    changed[field] = getattr(first, field)
    with pytest.raises(ValidationError, match="unique"):
        DatasetFixtureManifest(source=source(), records=(first, DatasetFixtureRecord(**changed)))


def test_fixture_manifest_requires_reviewed_byte_binding() -> None:
    row = manifest().records[0].model_dump()
    del row["expected_sha256"]
    with pytest.raises(ValidationError, match="expected_sha256"):
        DatasetFixtureRecord.model_validate(row)


def test_explicit_fixture_loader_does_not_relax_the_historical_loader(tmp_path: Path) -> None:
    expected = manifest()
    path = tmp_path / "manifest.json"
    path.write_text(expected.model_dump_json(), encoding="utf-8")
    assert load_dataset_fixture_manifest(path) == expected
    with pytest.raises(ValueError, match="required schema"):
        load_dataset_manifest(path)
    with pytest.raises(ValueError, match="size limit"):
        load_dataset_fixture_manifest(path, max_bytes=5)
    path.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="UTF-8"):
        load_dataset_fixture_manifest(path)


@pytest.mark.parametrize("review", [LicenseReviewStatus.PENDING, LicenseReviewStatus.REJECTED])
def test_fixture_import_retains_human_review_gate(
    tmp_path: Path, review: LicenseReviewStatus,
) -> None:
    candidate = DatasetFixtureManifest(
        source=source(license_review=review), records=manifest().records,
    )
    with pytest.raises(ValueError, match="not approved"):
        import_local_dataset(candidate, root=tmp_path, intended_use=DatasetUse.TRAINING,
                             pseudonymization_key=KEY)


def test_fixture_import_retains_use_hash_and_text_gates(tmp_path: Path) -> None:
    (tmp_path / "owned.cfg").write_text(TEXT, encoding="utf-8", newline="")
    with pytest.raises(ValueError, match="does not permit"):
        import_local_dataset(manifest(), root=tmp_path, intended_use=DatasetUse.REDISTRIBUTION,
                             pseudonymization_key=KEY)
    (tmp_path / "owned.cfg").write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        import_local_dataset(manifest(), root=tmp_path, intended_use=DatasetUse.TRAINING,
                             pseudonymization_key=KEY)
    (tmp_path / "owned.cfg").write_bytes(b"\x00")
    with pytest.raises(ValueError, match="not a text file"):
        import_local_dataset(manifest(), root=tmp_path, intended_use=DatasetUse.TRAINING,
                             pseudonymization_key=KEY)


def test_fixture_import_applies_current_residual_gate(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="residual content"):
        imported(tmp_path, "hostname owned-router\npassword\n")


def test_fixture_import_parse_segment_and_dedup_keep_metadata_unknown(tmp_path: Path) -> None:
    row = imported(tmp_path)
    assert row.metadata_status == "unknown_source_fixture"
    assert row.source_collected_at == ACQUIRED
    for field in ("network_id", "site_id", "device_id", "captured_at", "device_role"):
        assert getattr(row, field) is None
        assert row.model_dump(mode="json")[field] is None
    assert "owned-router" not in row.model_dump_json()
    assert "10.0.0.0" not in row.sanitized_text
    assert ImportedDatasetFixtureRecord.model_validate_json(row.model_dump_json()) == row
    parsed = parse_configuration_with_coverage(
        row.sanitized_text, filename="owned.cfg", collected_at=row.source_collected_at,
    )
    assert parsed.canonical.device.vendor == Vendor.CISCO
    blocks = segment_configuration(row)
    assert "".join(block.text for block in blocks) == row.sanitized_text
    later = row.model_copy(update={
        "record_id": "record-000000000001", "source_collected_at": ACQUIRED + timedelta(days=1),
    })
    dedup = deduplicate_dataset((row, later))
    assert isinstance(dedup, DatasetFixtureDeduplicationResult)
    assert dedup.unique_count == 1 and dedup.exact_duplicate_count == 1
    assert dedup.unique_records[0].record_id == min(row.record_id, later.record_id)
    assert dedup == deduplicate_dataset((later, row))
    assert DatasetFixtureDeduplicationResult.model_validate_json(dedup.model_dump_json()) == dedup
    with pytest.raises(ValidationError):
        DatasetDeduplicationResult.model_validate_json(dedup.model_dump_json())


def test_fixture_collection_group_and_pseudonyms_are_not_physical_entities(tmp_path: Path) -> None:
    row = imported(tmp_path)
    second = imported(tmp_path, TEXT.replace("owned-router", "other-router"))
    assert row.collection_group_id == second.collection_group_id
    assert row.network_id is second.network_id is None
    assert row.device_id is second.device_id is None


def test_unknown_fixtures_fail_closed_at_observed_corpus_consumers(tmp_path: Path) -> None:
    row = imported(tmp_path)
    dedup = deduplicate_dataset((row,))
    with pytest.raises(ValueError, match="observed device metadata"):
        split_deduplicated_dataset((row,), dedup)
    with pytest.raises(ValueError, match="observed device metadata"):
        build_dataset_quality_report((row,), dedup, None, sources=(source(),),
                                     intended_use=DatasetUse.TRAINING)
    with pytest.raises(ValueError, match="observed device metadata"):
        write_dataset_artifact((row,), dedup, None, None,
                               output_root=tmp_path, artifact_name="must-not-exist")
    assert not (tmp_path / "must-not-exist").exists()
    with pytest.raises(ValueError, match="lineage contract"):
        mutate_configuration(row, (MutationType.REMOVED_STATIC_ROUTE,))


def test_fixture_and_observed_records_cannot_be_mixed(tmp_path: Path) -> None:
    fixture = imported(tmp_path)
    observed = ImportedDatasetRecord(
        source_id="owned-lab", record_id="owned-observation", network_id="owned-net",
        site_id="owned-site", device_id="owned-device", captured_at=ACQUIRED,
        vendor_hint=Vendor.CISCO, device_role=None, raw_sha256=fixture.raw_sha256,
        sanitized_sha256=fixture.sanitized_sha256, sanitized_text=fixture.sanitized_text,
        raw_byte_count=fixture.raw_byte_count, replacements=fixture.replacements,
        sanitization_version=fixture.sanitization_version,
    )
    with pytest.raises(ValueError, match="cannot be mixed"):
        deduplicate_dataset((fixture, observed))


@pytest.mark.parametrize("changes", [
    {"sanitized_sha256": "0" * 64},
    {"sanitization_version": "config-sanitizer-9.0.0"},
    {"sanitized_text": "hostname visible-owned-value\n"},
])
def test_fixture_dedup_rechecks_content_hash_and_version(tmp_path: Path, changes: dict) -> None:
    row = imported(tmp_path).model_copy(update=changes)
    with pytest.raises(ValueError, match="content/hash/version"):
        deduplicate_dataset((row,))


@pytest.mark.parametrize("field", ["network_id", "captured_at"])
def test_fixture_dedup_revalidates_bypassed_metadata(tmp_path: Path, field: str) -> None:
    row = imported(tmp_path).model_copy(update={field: "invented-owned-value"})
    with pytest.raises(ValueError, match="metadata is invalid"):
        deduplicate_dataset((row,))


def test_fixture_import_revalidates_bypassed_manifest_metadata(tmp_path: Path) -> None:
    candidate = manifest()
    changed = candidate.model_copy(update={
        "records": (candidate.records[0].model_copy(update={"network_id": "invented"}),),
    })
    with pytest.raises(ValueError, match="required schema"):
        import_local_dataset(changed, root=tmp_path, intended_use=DatasetUse.TRAINING,
                             pseudonymization_key=KEY)
