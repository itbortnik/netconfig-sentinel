"""Strict source-manifest and sanitized import contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from app.domain import Vendor
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class DatasetSourceType(StrEnum):
    """Approved high-level origins for candidate configurations."""

    OPEN_REPOSITORY = "open_repository"
    BATFISH_TEST = "batfish_test"
    LAB = "lab"
    GENERATED = "generated"
    AUTHORIZED_REAL = "authorized_real"


class DatasetUse(StrEnum):
    """Uses which a source owner or license may explicitly permit."""

    RESEARCH = "research"
    TRAINING = "training"
    EVALUATION = "evaluation"
    REDISTRIBUTION = "redistribution"
    DERIVATIVE_WORKS = "derivative_works"


class LicenseReviewStatus(StrEnum):
    """Human review state for source licensing and authorization."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class DatasetSource(BaseModel):
    """Provenance, license, and authorization for one source collection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    source_type: DatasetSourceType
    origin: str = Field(min_length=1, max_length=2048)
    license_id: str = Field(min_length=1, max_length=256)
    license_url: str | None = Field(default=None, max_length=2048)
    license_review: LicenseReviewStatus
    allowed_uses: frozenset[DatasetUse] = Field(min_length=1)
    collected_at: datetime
    authorization_reference: str | None = Field(default=None, max_length=512)

    @field_validator("collected_at")
    @classmethod
    def collected_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")
        return value

    @model_validator(mode="after")
    def real_sources_require_authorization(self) -> DatasetSource:
        if (
            self.source_type is DatasetSourceType.AUTHORIZED_REAL
            and not self.authorization_reference
        ):
            raise ValueError("authorized real sources require an authorization reference")
        if (
            self.license_review is LicenseReviewStatus.APPROVED
            and self.license_id.strip().lower() in {"unknown", "unlicensed", "none"}
        ):
            raise ValueError("approved sources require an identified license")
        return self


class DatasetRecord(BaseModel):
    """One candidate file and its grouping metadata within a source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
    relative_path: str = Field(min_length=1, max_length=512)
    network_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    captured_at: datetime
    vendor_hint: Vendor | None = None
    device_role: str | None = Field(default=None, max_length=128)
    expected_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @field_validator("relative_path")
    @classmethod
    def relative_path_must_be_safe(cls, value: str) -> str:
        if "\\" in value or value.startswith("/"):
            raise ValueError("relative_path must use POSIX separators")
        parts = value.split("/")
        unsafe_part = any(
            part in {"", ".", ".."} or ":" in part for part in parts
        )
        if unsafe_part:
            raise ValueError("relative_path must stay inside the dataset root")
        return "/".join(parts)

    @field_validator("captured_at")
    @classmethod
    def captured_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")
        return value


class DatasetManifest(BaseModel):
    """Versioned manifest for one reviewed source and its candidate files."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    source: DatasetSource
    records: tuple[DatasetRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def records_must_be_unique(self) -> DatasetManifest:
        record_ids = [record.record_id for record in self.records]
        paths = [record.relative_path for record in self.records]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("record_id values must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("relative_path values must be unique")
        return self


class ImportedDatasetRecord(BaseModel):
    """Sanitized in-memory record safe to pass to later dataset stages."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    record_id: str
    network_id: str
    site_id: str
    device_id: str
    captured_at: datetime
    vendor_hint: Vendor | None
    device_role: str | None
    raw_sha256: str = Field(pattern=SHA256_PATTERN)
    sanitized_sha256: str = Field(pattern=SHA256_PATTERN)
    sanitized_text: str
    raw_byte_count: int = Field(ge=1)
    replacements: dict[str, int]
    sanitization_version: str
