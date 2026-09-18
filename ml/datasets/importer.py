"""Secure local dataset import which returns sanitized records only."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from ml.datasets.models import (
    DatasetManifest,
    DatasetRecord,
    DatasetUse,
    ImportedDatasetRecord,
    LicenseReviewStatus,
)
from ml.preprocessing import (
    SanitizationPolicy,
    pseudonymize_identifier,
    sanitize_configuration,
)

SUPPORTED_CONFIG_EXTENSIONS = frozenset({".cfg", ".conf", ".txt"})
DEFAULT_MAX_CONFIG_BYTES = 1024 * 1024
DEFAULT_MAX_MANIFEST_BYTES = 1024 * 1024


def load_dataset_manifest(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
) -> DatasetManifest:
    """Load a bounded UTF-8 JSON manifest with strict schema validation."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    with path.open("rb") as manifest_file:
        data = manifest_file.read(max_bytes + 1)
    if not data:
        raise ValueError("dataset manifest must not be empty")
    if len(data) > max_bytes:
        raise ValueError("dataset manifest exceeds the size limit")
    if _contains_disallowed_control(data):
        raise ValueError("dataset manifest must be a text JSON document")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("dataset manifest must be valid UTF-8") from error
    try:
        return DatasetManifest.model_validate_json(text)
    except ValidationError as error:
        raise ValueError("dataset manifest does not match the required schema") from error


def import_local_dataset(
    manifest: DatasetManifest,
    *,
    root: Path,
    intended_use: DatasetUse,
    pseudonymization_key: bytes,
    sanitization_policy: SanitizationPolicy | None = None,
    max_config_bytes: int = DEFAULT_MAX_CONFIG_BYTES,
) -> tuple[ImportedDatasetRecord, ...]:
    """Validate, read, and sanitize reviewed local configuration candidates."""

    if manifest.source.license_review is not LicenseReviewStatus.APPROVED:
        raise ValueError("dataset source license or authorization is not approved")
    if intended_use not in manifest.source.allowed_uses:
        raise ValueError(f"dataset source does not permit {intended_use.value}")
    if max_config_bytes < 1:
        raise ValueError("max_config_bytes must be positive")
    if len(pseudonymization_key) < 16:
        raise ValueError("pseudonymization_key must contain at least 16 bytes")

    try:
        resolved_root = root.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError("dataset root does not exist") from error
    if not resolved_root.is_dir():
        raise ValueError("dataset root must be a directory")

    effective_policy = sanitization_policy or SanitizationPolicy()
    imported: list[ImportedDatasetRecord] = []
    for record in manifest.records:
        source_path = _resolve_record_path(resolved_root, record)
        if source_path.suffix.lower() not in SUPPORTED_CONFIG_EXTENSIONS:
            raise ValueError(
                f"unsupported configuration extension for record {record.record_id}"
            )
        with source_path.open("rb") as configuration_file:
            data = configuration_file.read(max_config_bytes + 1)
        if not data:
            raise ValueError(f"configuration {record.record_id} must not be empty")
        if len(data) > max_config_bytes:
            raise ValueError(f"configuration {record.record_id} exceeds the size limit")
        if _contains_disallowed_control(data):
            raise ValueError(f"configuration {record.record_id} is not a text file")
        raw_sha256 = hashlib.sha256(data).hexdigest()
        if record.expected_sha256 is not None and raw_sha256 != record.expected_sha256:
            raise ValueError(f"configuration hash mismatch for record {record.record_id}")
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"configuration {record.record_id} must be valid UTF-8"
            ) from error
        topology_scope = f"{manifest.source.source_id}\0{record.network_id}"
        sanitized = sanitize_configuration(
            text,
            topology_id=topology_scope,
            pseudonymization_key=pseudonymization_key,
            policy=effective_policy,
        )
        sanitized_bytes = sanitized.text.encode("utf-8")
        imported.append(
            ImportedDatasetRecord(
                source_id=manifest.source.source_id,
                record_id=pseudonymize_identifier(
                    record.record_id,
                    kind="record",
                    scope_id=manifest.source.source_id,
                    pseudonymization_key=pseudonymization_key,
                ),
                network_id=pseudonymize_identifier(
                    record.network_id,
                    kind="network",
                    scope_id=manifest.source.source_id,
                    pseudonymization_key=pseudonymization_key,
                ),
                site_id=pseudonymize_identifier(
                    record.site_id,
                    kind="site",
                    scope_id=topology_scope,
                    pseudonymization_key=pseudonymization_key,
                ),
                device_id=pseudonymize_identifier(
                    record.device_id,
                    kind="device",
                    scope_id=topology_scope,
                    pseudonymization_key=pseudonymization_key,
                ),
                captured_at=record.captured_at,
                vendor_hint=record.vendor_hint,
                device_role=record.device_role,
                raw_sha256=raw_sha256,
                sanitized_sha256=hashlib.sha256(sanitized_bytes).hexdigest(),
                sanitized_text=sanitized.text,
                raw_byte_count=len(data),
                replacements=sanitized.replacements,
                sanitization_version=sanitized.version,
            )
        )
    return tuple(imported)


def _resolve_record_path(root: Path, record: DatasetRecord) -> Path:
    candidate = root
    for part in PurePosixPath(record.relative_path).parts:
        candidate /= part
        if candidate.is_symlink():
            raise ValueError(f"symbolic links are not allowed for record {record.record_id}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError(f"configuration file is missing for record {record.record_id}") from error
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(
            f"configuration path escapes the root for record {record.record_id}"
        ) from error
    if not resolved.is_file():
        raise ValueError(f"configuration path is not a file for record {record.record_id}")
    return resolved


def _contains_disallowed_control(data: bytes) -> bool:
    return any(byte < 32 and byte not in {9, 10, 13} for byte in data) or b"\x7f" in data
