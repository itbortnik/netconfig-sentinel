"""Reviewed fixtures as one conservative train-only collection, never fake splits."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from app.domain import Vendor
from app.parsers import detect_vendor
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ml.datasets.deduplication import (
    DatasetRecordReference,
    DeduplicationFingerprint,
    DeduplicationPolicy,
    deduplicate_dataset,
)
from ml.datasets.models import (
    DatasetFixtureManifest,
    DatasetSource,
    DatasetSourceType,
    DatasetUse,
    ImportedDatasetFixtureRecord,
    LicenseReviewStatus,
)
from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.blocks import digest, segment_configuration


class FixtureTrainingPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    structural_refusals: Literal["reject", "exclude"] = "reject"
    max_records: int = Field(default=512, ge=1, le=2048, strict=True)
    deduplication: DeduplicationPolicy = Field(default_factory=DeduplicationPolicy)


class FixtureTrainingExclusion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    record: DatasetRecordReference
    sanitized_sha256: Digest
    reason: Literal["structural_segmentation_refusal"] = "structural_segmentation_refusal"


class FixtureTrainingAudit(BaseModel):
    """Content/exposure inventory, not independent networks or human-label evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["config-fixture-corpus-0.1.0"] = "config-fixture-corpus-0.1.0"
    partition: Literal["train_only"] = "train_only"
    source: DatasetSource
    manifest_fingerprint: Digest
    deduplication_fingerprint: Digest
    policy: FixtureTrainingPolicy
    collection_group_id: str = Field(pattern=r"^collection-[0-9a-f]{12}$")
    input_count: int = Field(ge=1)
    unique_count: int = Field(ge=1)
    training_count: int = Field(ge=1)
    block_count: int = Field(ge=1)
    training_fingerprint: Digest
    input_fingerprints: tuple[DeduplicationFingerprint, ...]
    training_records: tuple[DatasetRecordReference, ...]
    exclusions: tuple[FixtureTrainingExclusion, ...]
    independent_network_count: None = None
    device_count: None = None
    capture_time_range: None = None
    confirmed_anomaly_count: None = None
    heldout_isolation_verified: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self) -> FixtureTrainingAudit:
        if (
            self.source.license_review is not LicenseReviewStatus.APPROVED
            or self.source.source_type
            not in {
                DatasetSourceType.BATFISH_TEST,
                DatasetSourceType.OPEN_REPOSITORY,
                DatasetSourceType.GENERATED,
            }
            or DatasetUse.TRAINING not in self.source.allowed_uses
            or self.input_count != len(self.input_fingerprints)
            or self.training_count != len(self.training_records)
            or self.unique_count != self.training_count + len(self.exclusions)
            or self.unique_count > self.input_count
            or self.input_count > self.policy.max_records
            or (self.exclusions and self.policy.structural_refusals != "exclude")
        ):
            raise ValueError("fixture training audit counts/permissions are inconsistent")
        inventory = {item.record for item in self.input_fingerprints}
        trained, excluded = set(self.training_records), {item.record for item in self.exclusions}
        if (
            len(inventory) != self.input_count
            or len(trained) != self.training_count
            or len(excluded) != len(self.exclusions)
            or trained & excluded
            or not (trained | excluded) <= inventory
            or any(item.source_id != self.source.source_id for item in inventory)
            or any(
                item.sanitized_sha256
                != next(
                    row.sanitized_sha256
                    for row in self.input_fingerprints
                    if row.record == item.record
                )
                for item in self.exclusions
            )
        ):
            raise ValueError("fixture training exposure references are inconsistent")
        fingerprints = {item.record: item for item in self.input_fingerprints}
        if self.training_fingerprint != digest(
            json.dumps(
                [
                    (item.source_id, item.record_id, fingerprints[item].sanitized_sha256)
                    for item in self.training_records
                ],
                separators=(",", ":"),
            )
        ):
            raise ValueError("fixture training source fingerprint differs from exposure inventory")
        return self


@dataclass(frozen=True)
class FixtureTrainingCorpus:
    """Private in-memory inputs; every consumer rebuilds the content-bound audit."""

    manifest: DatasetFixtureManifest
    imported: tuple[ImportedDatasetFixtureRecord, ...]
    records: tuple[ImportedDatasetFixtureRecord, ...]
    audit: FixtureTrainingAudit


def prepare_fixture_training_corpus(
    manifest: DatasetFixtureManifest,
    records: tuple[ImportedDatasetFixtureRecord, ...],
    *,
    policy: FixtureTrainingPolicy | None = None,
) -> FixtureTrainingCorpus:
    """Audit complete intake, deduplicate first, then apply predeclared structural holds."""
    effective = FixtureTrainingPolicy.model_validate(
        (policy or FixtureTrainingPolicy()).model_dump(),
    )
    try:
        manifest = DatasetFixtureManifest.model_validate(manifest.model_dump(warnings=False))
        records = tuple(
            ImportedDatasetFixtureRecord.model_validate(row.model_dump(warnings=False))
            for row in records
        )
    except (ValidationError, AttributeError):
        raise ValueError("fixture training inputs do not match the required schema") from None
    source = manifest.source
    if source.license_review is not LicenseReviewStatus.APPROVED:
        raise ValueError("fixture training source is not approved")
    if DatasetUse.TRAINING not in source.allowed_uses:
        raise ValueError("fixture source does not permit training")
    if not records or len(records) > effective.max_records:
        raise ValueError("fixture training record budget exceeded or empty corpus")
    if Counter((row.expected_sha256, row.vendor_hint) for row in manifest.records) != Counter(
        (row.raw_sha256, row.vendor_hint) for row in records
    ) or any(
        row.source_id != source.source_id or row.source_collected_at != source.collected_at
        for row in records
    ):
        raise ValueError("fixture training inputs do not match the complete source manifest")
    groups = {row.collection_group_id for row in records}
    if len(groups) != 1:
        raise ValueError("one unknown source collection cannot be divided into entity groups")
    if any(row.vendor_hint not in (Vendor.CISCO, Vendor.JUNIPER) for row in records):
        raise ValueError("fixture training requires an explicit supported vendor")
    for row in records:
        if not row.sanitized_text.strip() or len(row.sanitized_text.encode("utf-8")) > 1024 * 1024:
            raise ValueError("fixture training text must be nonempty and bounded to 1 MiB")
        detected = detect_vendor(row.sanitized_text).parser_key
        expected = Vendor.CISCO if detected == "cisco_ios" else Vendor.JUNIPER
        if row.vendor_hint != expected:
            raise ValueError("fixture training vendor hint disagrees with content")
    # Shared deduplication revalidates current sanitization/content/hash before model exposure.
    dedup = deduplicate_dataset(records, policy=effective.deduplication)
    selected, exclusions, blocks = [], [], 0
    for row in sorted(dedup.unique_records, key=lambda item: (item.source_id, item.record_id)):
        try:
            segmented = segment_configuration(row)
        except ValueError:
            if effective.structural_refusals != "exclude":
                raise ValueError("fixture corpus has a structural segmentation refusal") from None
            exclusions.append(
                FixtureTrainingExclusion(
                    record=DatasetRecordReference(source_id=row.source_id, record_id=row.record_id),
                    sanitized_sha256=row.sanitized_sha256,
                )
            )
            continue
        selected.append(row)
        blocks += len(segmented)
    if not selected or not blocks:
        raise ValueError("fixture corpus has no segmentable training content")
    # Sets must be canonical across processes; order in source JSON is not evidence.
    manifest_payload = manifest.model_dump(mode="json")
    manifest_payload["source"]["allowed_uses"] = sorted(source.allowed_uses)
    audit = FixtureTrainingAudit(
        source=source,
        manifest_fingerprint=canonical_hash(manifest_payload),
        deduplication_fingerprint=canonical_hash(dedup.model_dump(mode="json")),
        policy=effective,
        collection_group_id=next(iter(groups)),
        input_count=len(records),
        unique_count=dedup.unique_count,
        training_count=len(selected),
        block_count=blocks,
        training_fingerprint=training_source_fingerprint(tuple(selected)),
        input_fingerprints=dedup.fingerprints,
        training_records=tuple(
            DatasetRecordReference(source_id=row.source_id, record_id=row.record_id)
            for row in selected
        ),
        exclusions=tuple(exclusions),
    )
    return FixtureTrainingCorpus(manifest, records, tuple(selected), audit)


def validate_fixture_training_corpus(corpus: FixtureTrainingCorpus) -> FixtureTrainingCorpus:
    """No dataclass/model-copy shortcut can add content, permission or fake metadata."""
    if not isinstance(corpus, FixtureTrainingCorpus):
        raise ValueError("an explicit fixture training corpus is required")
    rebuilt = prepare_fixture_training_corpus(
        corpus.manifest,
        corpus.imported,
        policy=corpus.audit.policy,
    )
    if rebuilt.audit != corpus.audit or rebuilt.records != corpus.records:
        raise ValueError("fixture corpus content/exposure audit mismatch")
    return rebuilt


def training_source_fingerprint(records: tuple[ImportedDatasetFixtureRecord, ...]) -> str:
    return digest(
        json.dumps(
            [(row.source_id, row.record_id, row.sanitized_sha256) for row in records],
            separators=(",", ":"),
        )
    )
