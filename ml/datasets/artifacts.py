"""Write and verify non-overwriting sanitized dataset artifact directories."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ml.datasets.deduplication import DatasetDeduplicationResult
from ml.datasets.models import DatasetUse, ImportedDatasetRecord
from ml.datasets.quality import (
    DatasetQualityReport,
    compute_pipeline_fingerprint,
)
from ml.datasets.splitting import DatasetSplitResult

ARTIFACT_FORMAT_VERSION = "sanitized-dataset-artifact-0.1.0"
DEFAULT_MAX_ARTIFACT_MANIFEST_BYTES = 2 * 1024 * 1024
_ARTIFACT_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


class ArtifactFileEntry(BaseModel):
    """Integrity metadata for one file inside an artifact directory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_count: int = Field(ge=1)
    media_type: str = Field(min_length=1, max_length=128)
    record_count: int | None = Field(default=None, ge=0)

    @field_validator("path")
    @classmethod
    def path_must_be_safe(cls, value: str) -> str:
        if "\\" in value or value.startswith("/"):
            raise ValueError("artifact paths must use relative POSIX syntax")
        parts = value.split("/")
        if any(part in {"", ".", ".."} or ":" in part for part in parts):
            raise ValueError("artifact path must stay inside its directory")
        return "/".join(parts)


class DatasetArtifactManifest(BaseModel):
    """Self-contained integrity manifest written after all content files."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = Field(
        default=ARTIFACT_FORMAT_VERSION,
        pattern=r"^sanitized-dataset-artifact-0\.1\.0$",
    )
    artifact_id: str = Field(pattern=r"^artifact-[0-9a-f]{24}$")
    pipeline_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    intended_use: DatasetUse
    source_ids: tuple[str, ...] = Field(min_length=1)
    input_count: int = Field(ge=3)
    unique_count: int = Field(ge=3)
    pipeline_versions: dict[str, str]
    files: tuple[ArtifactFileEntry, ...] = Field(min_length=1)
    complete: bool = True

    @model_validator(mode="after")
    def manifest_must_be_complete_and_unique(self) -> DatasetArtifactManifest:
        if not self.complete:
            raise ValueError("artifact manifest must describe a complete artifact")
        if len(self.source_ids) != len(set(self.source_ids)):
            raise ValueError("artifact source IDs must be unique")
        if self.source_ids != tuple(sorted(self.source_ids)):
            raise ValueError("artifact source IDs must be sorted")
        paths = [entry.path for entry in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact file paths must be unique")
        if paths != sorted(paths):
            raise ValueError("artifact file entries must be sorted")
        required_versions = {
            "sanitization",
            "deduplication",
            "splitting",
            "quality_report",
        }
        if set(self.pipeline_versions) != required_versions or any(
            not value for value in self.pipeline_versions.values()
        ):
            raise ValueError("artifact pipeline versions are incomplete")
        if self.unique_count > self.input_count:
            raise ValueError("artifact unique count exceeds input count")
        if self.artifact_id != _artifact_id(self.pipeline_fingerprint, list(self.files)):
            raise ValueError("artifact ID does not match its content entries")
        return self


class DatasetArtifactWriteResult(BaseModel):
    """Location and verified manifest of a newly finalized artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    manifest: DatasetArtifactManifest


def write_dataset_artifact(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    deduplication: DatasetDeduplicationResult,
    split_result: DatasetSplitResult,
    quality_report: DatasetQualityReport,
    *,
    output_root: Path,
    artifact_name: str,
) -> DatasetArtifactWriteResult:
    """Persist sanitized representatives and audit data without overwriting."""

    if not quality_report.technically_valid:
        raise ValueError("blocking quality issues prevent artifact persistence")
    fingerprint = compute_pipeline_fingerprint(records, deduplication, split_result)
    if fingerprint != quality_report.pipeline_fingerprint:
        raise ValueError("quality report does not match the supplied pipeline outputs")
    if quality_report.metrics.candidate_configuration_count != len(records):
        raise ValueError("quality report candidate count does not match records")
    if quality_report.metrics.unique_configuration_count != deduplication.unique_count:
        raise ValueError("quality report unique count does not match deduplication")
    record_source_ids = tuple(sorted({record.source_id for record in records}))
    report_source_ids = tuple(source.source_id for source in quality_report.sources)
    if report_source_ids != record_source_ids:
        raise ValueError("quality report does not include every artifact source")
    for source in quality_report.sources:
        if source.license_review.value != "approved":
            raise ValueError("artifact sources must have approved license review")
        if quality_report.intended_use not in source.allowed_uses:
            raise ValueError("artifact source does not permit the intended use")
    if not _ARTIFACT_NAME.fullmatch(artifact_name):
        raise ValueError("artifact_name must be a safe filesystem leaf")

    try:
        resolved_root = output_root.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError("artifact output root does not exist") from error
    if not resolved_root.is_dir():
        raise ValueError("artifact output root must be a directory")
    target = resolved_root / artifact_name
    if target.exists() or target.is_symlink():
        raise FileExistsError("artifact target already exists and will not be overwritten")
    target.mkdir()
    incomplete_marker = target / ".incomplete"
    _write_bytes_exclusive(incomplete_marker, b"incomplete\n")
    (target / "records").mkdir()
    (target / "audit").mkdir()

    entries: list[ArtifactFileEntry] = []
    for partition in split_result.partitions:
        entries.append(
            _write_json_lines(
                target,
                f"records/{partition.split.value}.jsonl",
                partition.records,
            )
        )
    entries.append(
        _write_json_document(
            target,
            "audit/deduplication.json",
            _deduplication_audit_payload(deduplication),
        )
    )
    entries.append(
        _write_json_document(
            target,
            "audit/splitting.json",
            _splitting_audit_payload(split_result),
        )
    )
    entries.append(
        _write_json_document(
            target,
            "quality-report.json",
            quality_report,
        )
    )
    entries.sort(key=lambda entry: entry.path)
    artifact_id = _artifact_id(fingerprint, entries)
    manifest = DatasetArtifactManifest(
        artifact_id=artifact_id,
        pipeline_fingerprint=fingerprint,
        intended_use=quality_report.intended_use,
        source_ids=tuple(source.source_id for source in quality_report.sources),
        input_count=len(records),
        unique_count=deduplication.unique_count,
        pipeline_versions={
            "sanitization": _single_sanitization_version(records),
            "deduplication": deduplication.algorithm_version,
            "splitting": split_result.algorithm_version,
            "quality_report": quality_report.report_version,
        },
        files=tuple(entries),
    )
    _write_json_document(target, "manifest.json", manifest)
    incomplete_marker.unlink()
    verified = load_dataset_artifact(target)
    return DatasetArtifactWriteResult(path=target, manifest=verified)


def load_dataset_artifact(
    path: Path,
    *,
    max_manifest_bytes: int = DEFAULT_MAX_ARTIFACT_MANIFEST_BYTES,
) -> DatasetArtifactManifest:
    """Verify completeness, file inventory, byte counts, and SHA-256 values."""

    if max_manifest_bytes < 1:
        raise ValueError("max_manifest_bytes must be positive")
    if path.is_symlink():
        raise ValueError("artifact directory must not be a symbolic link")
    try:
        root = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError("artifact directory does not exist") from error
    if not root.is_dir():
        raise ValueError("artifact path must be a directory")
    if (root / ".incomplete").exists():
        raise ValueError("artifact is incomplete")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("artifact manifest is missing or unsafe")
    with manifest_path.open("rb") as manifest_file:
        manifest_bytes = manifest_file.read(max_manifest_bytes + 1)
    if not manifest_bytes or len(manifest_bytes) > max_manifest_bytes:
        raise ValueError("artifact manifest is empty or exceeds the size limit")
    try:
        manifest = DatasetArtifactManifest.model_validate_json(manifest_bytes)
    except ValidationError as error:
        raise ValueError("artifact manifest does not match the required schema") from error

    expected_files = {entry.path for entry in manifest.files} | {"manifest.json"}
    observed_files: set[str] = set()
    for item in root.rglob("*"):
        if item.is_symlink():
            raise ValueError("artifact must not contain symbolic links")
        if item.is_file():
            observed_files.add(item.relative_to(root).as_posix())
    if observed_files != expected_files:
        raise ValueError("artifact file inventory does not match the manifest")
    for entry in manifest.files:
        file_path = _artifact_file_path(root, entry.path, require_absent=False)
        byte_count, sha256 = _hash_file(file_path)
        if byte_count != entry.byte_count or sha256 != entry.sha256:
            raise ValueError(f"artifact integrity check failed for {entry.path}")
    return manifest


def _write_json_lines(
    root: Path,
    relative_path: str,
    records: tuple[ImportedDatasetRecord, ...],
) -> ArtifactFileEntry:
    path = _artifact_file_path(root, relative_path)
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("xb") as output:
        for record in records:
            line = _canonical_json_bytes(record)
            output.write(line)
            digest.update(line)
            byte_count += len(line)
        output.flush()
        os.fsync(output.fileno())
    return ArtifactFileEntry(
        path=relative_path,
        sha256=digest.hexdigest(),
        byte_count=byte_count,
        media_type="application/x-ndjson",
        record_count=len(records),
    )


def _write_json_document(
    root: Path,
    relative_path: str,
    value: object,
) -> ArtifactFileEntry:
    data = _canonical_json_bytes(value)
    path = _artifact_file_path(root, relative_path)
    _write_bytes_exclusive(path, data)
    return ArtifactFileEntry(
        path=relative_path,
        sha256=hashlib.sha256(data).hexdigest(),
        byte_count=len(data),
        media_type="application/json",
    )


def _write_bytes_exclusive(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _canonical_json_bytes(value: object) -> bytes:
    encoded = json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return (encoded + "\n").encode("utf-8")


def _json_value(value: object) -> Any:
    if isinstance(value, BaseModel):
        return {
            name: _json_value(getattr(value, name))
            for name in type(value).model_fields
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        return {str(_json_value(key)): _json_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        converted = [_json_value(item) for item in value]
        return sorted(converted, key=_json_sort_key)
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _json_sort_key(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _deduplication_audit_payload(
    deduplication: DatasetDeduplicationResult,
) -> dict[str, object]:
    return {
        "algorithm_version": deduplication.algorithm_version,
        "policy": deduplication.policy,
        "input_count": deduplication.input_count,
        "unique_count": deduplication.unique_count,
        "exact_duplicate_count": deduplication.exact_duplicate_count,
        "near_duplicate_count": deduplication.near_duplicate_count,
        "template_group_count": deduplication.template_group_count,
        "fingerprints": deduplication.fingerprints,
        "duplicate_clusters": deduplication.duplicate_clusters,
        "template_groups": deduplication.template_groups,
    }


def _splitting_audit_payload(split_result: DatasetSplitResult) -> dict[str, object]:
    partition_summaries = [
        {
            name: getattr(partition, name)
            for name in type(partition).model_fields
            if name != "records"
        }
        for partition in split_result.partitions
    ]
    return {
        "algorithm_version": split_result.algorithm_version,
        "policy": split_result.policy,
        "input_count": split_result.input_count,
        "unique_count": split_result.unique_count,
        "cross_split_template_count": split_result.cross_split_template_count,
        "assignments": split_result.assignments,
        "atomic_groups": split_result.atomic_groups,
        "partitions": partition_summaries,
        "template_audit": split_result.template_audit,
        "temporal_audit": split_result.temporal_audit,
        "limitations": split_result.limitations,
    }


def _artifact_file_path(
    root: Path,
    relative_path: str,
    *,
    require_absent: bool = True,
) -> Path:
    safe_path = ArtifactFileEntry(
        path=relative_path,
        sha256="0" * 64,
        byte_count=1,
        media_type="application/octet-stream",
    ).path
    candidate = root.joinpath(*PurePosixPath(safe_path).parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(root)
    except ValueError as error:
        raise ValueError("artifact file path escapes its directory") from error
    if require_absent and (candidate.exists() or candidate.is_symlink()):
        raise FileExistsError(f"artifact file already exists: {relative_path}")
    if not require_absent and (candidate.is_symlink() or not candidate.is_file()):
        raise ValueError(f"artifact file is missing or unsafe: {relative_path}")
    return candidate


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
    return byte_count, digest.hexdigest()


def _artifact_id(
    pipeline_fingerprint: str,
    entries: list[ArtifactFileEntry],
) -> str:
    payload = "\0".join(
        [pipeline_fingerprint]
        + [f"{entry.path}\0{entry.sha256}\0{entry.byte_count}" for entry in entries]
    )
    return f"artifact-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:24]}"


def _single_sanitization_version(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
) -> str:
    versions = {record.sanitization_version for record in records}
    if len(versions) != 1:
        raise ValueError("artifact records must use one sanitization version")
    return next(iter(versions))
