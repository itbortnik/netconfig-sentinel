"""Tests for licensed source manifests and secure local dataset import."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.domain import Vendor
from pydantic import ValidationError

from ml.datasets import (
    DatasetManifest,
    DatasetRecord,
    DatasetSource,
    DatasetSourceType,
    DatasetUse,
    LicenseReviewStatus,
    import_local_dataset,
    load_dataset_manifest,
)

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
PSEUDONYMIZATION_KEY = b"unit-test-pseudonymization-key"


def _source(
    *,
    review: LicenseReviewStatus = LicenseReviewStatus.APPROVED,
    allowed_uses: frozenset[DatasetUse] = frozenset({DatasetUse.TRAINING}),
) -> DatasetSource:
    return DatasetSource(
        source_id="lab-fixtures",
        source_type=DatasetSourceType.LAB,
        origin="controlled local lab",
        license_id="CC0-1.0",
        license_url="https://creativecommons.org/publicdomain/zero/1.0/",
        license_review=review,
        allowed_uses=allowed_uses,
        collected_at=COLLECTED_AT,
    )


def _record(
    relative_path: str,
    payload: bytes,
    *,
    record_id: str = "edge-prod-01",
    device_id: str = "edge-prod-01",
    expected_sha256: str | None = None,
) -> DatasetRecord:
    return DatasetRecord(
        record_id=record_id,
        relative_path=relative_path,
        network_id="customer-primary-network",
        site_id="private-datacenter",
        device_id=device_id,
        captured_at=COLLECTED_AT,
        vendor_hint=Vendor.CISCO,
        device_role="edge-router",
        expected_sha256=expected_sha256 or hashlib.sha256(payload).hexdigest(),
    )


def test_source_manifest_enforces_authorization_and_license_review() -> None:
    common = {
        "source_id": "authorized-production",
        "source_type": DatasetSourceType.AUTHORIZED_REAL,
        "origin": "approved customer export",
        "license_id": "CUSTOM-AUTHORIZATION",
        "license_review": LicenseReviewStatus.APPROVED,
        "allowed_uses": frozenset({DatasetUse.EVALUATION}),
        "collected_at": COLLECTED_AT,
    }

    with pytest.raises(ValidationError, match="authorization reference"):
        DatasetSource(**common)
    with pytest.raises(ValidationError, match="identified license"):
        DatasetSource(
            **{
                **common,
                "source_type": DatasetSourceType.LAB,
                "license_id": "unknown",
            }
        )


@pytest.mark.parametrize(
    "relative_path",
    (
        "../device.cfg",
        "configs/./device.cfg",
        "configs//device.cfg",
        "/absolute/device.cfg",
        "C:/absolute/device.cfg",
        "configs\\device.cfg",
    ),
)
def test_record_rejects_unsafe_relative_paths(relative_path: str) -> None:
    with pytest.raises(ValidationError, match="relative_path"):
        _record(relative_path, b"hostname edge\n")


def test_manifest_rejects_duplicate_record_ids_and_paths() -> None:
    payload = b"hostname edge\n"
    first = _record("configs/first.cfg", payload)
    duplicate_id = _record("configs/second.cfg", payload)
    duplicate_path = _record(
        "configs/first.cfg",
        payload,
        record_id="edge-prod-02",
        device_id="edge-prod-02",
    )

    with pytest.raises(ValidationError, match="record_id values"):
        DatasetManifest(source=_source(), records=(first, duplicate_id))
    with pytest.raises(ValidationError, match="relative_path values"):
        DatasetManifest(source=_source(), records=(first, duplicate_path))


def test_manifest_loader_is_bounded_utf8_and_strict(tmp_path: Path) -> None:
    payload = b"hostname edge\n"
    manifest = DatasetManifest(
        source=_source(),
        records=(_record("configs/edge.cfg", payload),),
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    assert load_dataset_manifest(manifest_path) == manifest
    with pytest.raises(ValueError, match="size limit"):
        load_dataset_manifest(manifest_path, max_bytes=10)

    document = json.loads(manifest.model_dump_json())
    document["unexpected"] = True
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="required schema"):
        load_dataset_manifest(manifest_path)

    manifest_path.write_bytes(b"{\x00}")
    with pytest.raises(ValueError, match="text JSON"):
        load_dataset_manifest(manifest_path)


def test_import_returns_only_sanitized_and_pseudonymous_records(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    configs = root / "configs"
    configs.mkdir(parents=True)
    first_payload = (
        b"hostname edge-prod-01\n"
        b"username administrator secret 9 PRIVATE-HASH\n"
        b"interface GigabitEthernet0/1\n"
        b" ip address 10.20.30.1 255.255.255.0\n"
    )
    second_payload = (
        b"hostname edge-prod-02\n"
        b"interface GigabitEthernet0/2\n"
        b" ip address 10.20.30.2 255.255.255.0\n"
    )
    (configs / "first.cfg").write_bytes(first_payload)
    (configs / "second.cfg").write_bytes(second_payload)
    manifest = DatasetManifest(
        source=_source(),
        records=(
            _record("configs/first.cfg", first_payload),
            _record(
                "configs/second.cfg",
                second_payload,
                record_id="edge-prod-02",
                device_id="edge-prod-02",
            ),
        ),
    )

    imported = import_local_dataset(
        manifest,
        root=root,
        intended_use=DatasetUse.TRAINING,
        pseudonymization_key=PSEUDONYMIZATION_KEY,
    )

    assert len(imported) == 2
    first, second = imported
    assert first.record_id != "edge-prod-01"
    assert first.network_id == second.network_id
    assert first.site_id == second.site_id
    assert first.device_id != second.device_id
    assert "edge-prod-01" not in first.sanitized_text
    assert "administrator" not in first.sanitized_text
    assert "PRIVATE-HASH" not in first.sanitized_text
    assert "10.20.30.1" not in first.sanitized_text
    assert first.raw_sha256 == hashlib.sha256(first_payload).hexdigest()
    assert first.sanitized_sha256 == hashlib.sha256(
        first.sanitized_text.encode("utf-8")
    ).hexdigest()
    assert first.raw_byte_count == len(first_payload)
    assert "relative_path" not in first.model_dump()
    assert "raw_text" not in first.model_dump()
    assert (configs / "first.cfg").read_bytes() == first_payload


def test_import_requires_approved_and_permitted_source(tmp_path: Path) -> None:
    payload = b"hostname edge\n"
    path = tmp_path / "edge.cfg"
    path.write_bytes(payload)
    record = _record("edge.cfg", payload)
    pending = DatasetManifest(
        source=_source(review=LicenseReviewStatus.PENDING), records=(record,)
    )
    research_only = DatasetManifest(
        source=_source(allowed_uses=frozenset({DatasetUse.RESEARCH})),
        records=(record,),
    )

    with pytest.raises(ValueError, match="not approved"):
        import_local_dataset(
            pending,
            root=tmp_path,
            intended_use=DatasetUse.TRAINING,
            pseudonymization_key=PSEUDONYMIZATION_KEY,
        )
    with pytest.raises(ValueError, match="does not permit training"):
        import_local_dataset(
            research_only,
            root=tmp_path,
            intended_use=DatasetUse.TRAINING,
            pseudonymization_key=PSEUDONYMIZATION_KEY,
        )


@pytest.mark.parametrize(
    ("filename", "payload", "expected_hash", "max_bytes", "message"),
    (
        ("edge.json", b"hostname edge\n", None, 1024, "unsupported"),
        ("edge.cfg", b"", None, 1024, "must not be empty"),
        ("edge.cfg", b"hostname edge\x00\n", None, 1024, "not a text file"),
        ("edge.cfg", b"\xff\xfe", None, 1024, "valid UTF-8"),
        ("edge.cfg", b"hostname edge\n", "0" * 64, 1024, "hash mismatch"),
        ("edge.cfg", b"hostname edge\n", None, 4, "size limit"),
    ),
)
def test_import_rejects_unsafe_or_invalid_files(
    tmp_path: Path,
    filename: str,
    payload: bytes,
    expected_hash: str | None,
    max_bytes: int,
    message: str,
) -> None:
    path = tmp_path / filename
    path.write_bytes(payload)
    record = _record(filename, payload, expected_sha256=expected_hash)
    manifest = DatasetManifest(source=_source(), records=(record,))

    with pytest.raises(ValueError, match=message):
        import_local_dataset(
            manifest,
            root=tmp_path,
            intended_use=DatasetUse.TRAINING,
            pseudonymization_key=PSEUDONYMIZATION_KEY,
            max_config_bytes=max_bytes,
        )
