"""Deterministic entity-isolated and chronological dataset splitting."""

from __future__ import annotations

import hashlib
from bisect import bisect_left
from collections import defaultdict
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from ml.datasets.deduplication import (
    DatasetDeduplicationResult,
    DatasetRecordReference,
)
from ml.datasets.models import ImportedDatasetRecord

SPLITTING_VERSION = "dataset-split-0.1.0"


def _require_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("split timestamps must include a timezone")
    return value


AwareDateTime = Annotated[datetime, AfterValidator(_require_aware_datetime)]


class DatasetSplit(StrEnum):
    """Supported corpus partitions."""

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


class DatasetSplitPolicy(BaseModel):
    """Recorded allocation targets and temporal safety mode."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    train_fraction: float = Field(default=0.70, gt=0.0, lt=1.0)
    validation_fraction: float = Field(default=0.15, gt=0.0, lt=1.0)
    test_fraction: float = Field(default=0.15, gt=0.0, lt=1.0)
    minimum_atomic_groups_per_split: int = Field(default=1, ge=1, le=1000)
    require_strict_temporal_order: bool = False

    @model_validator(mode="after")
    def fractions_must_sum_to_one(self) -> DatasetSplitPolicy:
        total = self.train_fraction + self.validation_fraction + self.test_fraction
        if abs(total - 1.0) > 1e-9:
            raise ValueError("train, validation, and test fractions must sum to 1")
        return self


class DatasetSplitAssignment(BaseModel):
    """Auditable split placement for an original sanitized candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record: DatasetRecordReference
    split: DatasetSplit
    atomic_group_id: str = Field(pattern=r"^split-group-[0-9a-f]{16}$")
    network_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    captured_at: AwareDateTime
    is_representative: bool


class AtomicSplitGroup(BaseModel):
    """Indivisible entity and duplicate component assigned as one unit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    group_id: str = Field(pattern=r"^split-group-[0-9a-f]{16}$")
    split: DatasetSplit
    members: tuple[DatasetRecordReference, ...] = Field(min_length=1)
    representative_count: int = Field(ge=1)
    first_captured_at: AwareDateTime
    last_captured_at: AwareDateTime

    @model_validator(mode="after")
    def group_must_be_consistent(self) -> AtomicSplitGroup:
        member_keys = [_reference_key(member) for member in self.members]
        if len(member_keys) != len(set(member_keys)):
            raise ValueError("atomic split group members must be unique")
        if self.group_id != _atomic_group_id(self.members):
            raise ValueError("atomic group ID must match its members")
        if self.first_captured_at > self.last_captured_at:
            raise ValueError("atomic group capture range is reversed")
        if self.representative_count > len(self.members):
            raise ValueError("representative count exceeds group membership")
        return self


class DatasetPartition(BaseModel):
    """Training-ready representatives and counts for one split."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    split: DatasetSplit
    target_fraction: float = Field(gt=0.0, lt=1.0)
    actual_fraction: float = Field(gt=0.0, le=1.0)
    source_record_count: int = Field(ge=1)
    atomic_group_count: int = Field(ge=1)
    network_count: int = Field(ge=1)
    site_count: int = Field(ge=1)
    device_count: int = Field(ge=1)
    first_captured_at: AwareDateTime
    last_captured_at: AwareDateTime
    records: tuple[ImportedDatasetRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def partition_must_be_consistent(self) -> DatasetPartition:
        references = [(record.source_id, record.record_id) for record in self.records]
        if len(references) != len(set(references)):
            raise ValueError("partition record references must be unique")
        if self.first_captured_at > self.last_captured_at:
            raise ValueError("partition capture range is reversed")
        return self


class TemplateSplitAudit(BaseModel):
    """Shows whether one broad configuration template spans partitions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    member_count: int = Field(ge=2)
    splits: frozenset[DatasetSplit] = Field(min_length=1)


class TemporalSplitAudit(BaseModel):
    """Observed time ranges after entity-isolated chronological allocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    train_last_captured_at: AwareDateTime
    validation_first_captured_at: AwareDateTime
    validation_last_captured_at: AwareDateTime
    test_first_captured_at: AwareDateTime
    strict_order: bool


class DatasetSplitResult(BaseModel):
    """Complete split artifact with representatives and leakage audit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm_version: str = Field(
        default=SPLITTING_VERSION,
        pattern=r"^dataset-split-0\.1\.0$",
    )
    policy: DatasetSplitPolicy
    input_count: int = Field(ge=3)
    unique_count: int = Field(ge=3)
    cross_split_template_count: int = Field(ge=0)
    assignments: tuple[DatasetSplitAssignment, ...] = Field(min_length=3)
    atomic_groups: tuple[AtomicSplitGroup, ...] = Field(min_length=3)
    partitions: tuple[DatasetPartition, ...] = Field(min_length=3, max_length=3)
    template_audit: tuple[TemplateSplitAudit, ...]
    temporal_audit: TemporalSplitAudit
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def payload_must_be_internally_consistent(self) -> DatasetSplitResult:
        if len(self.assignments) != self.input_count:
            raise ValueError("assignment count must equal input_count")
        assignment_by_reference = {
            _reference_key(item.record): item for item in self.assignments
        }
        if len(assignment_by_reference) != self.input_count:
            raise ValueError("assignment references must be unique")
        if {partition.split for partition in self.partitions} != set(DatasetSplit):
            raise ValueError("exactly one train, validation, and test partition is required")
        if sum(len(partition.records) for partition in self.partitions) != self.unique_count:
            raise ValueError("partition representatives must equal unique_count")
        partition_references: dict[tuple[str, str], DatasetSplit] = {}
        for partition in self.partitions:
            for record in partition.records:
                key = record.source_id, record.record_id
                if key in partition_references:
                    raise ValueError("representatives must occur in exactly one partition")
                partition_references[key] = partition.split
        representative_assignments = {
            key: assignment.split
            for key, assignment in assignment_by_reference.items()
            if assignment.is_representative
        }
        if partition_references != representative_assignments:
            raise ValueError("partition records must match representative assignments")

        group_members: set[tuple[str, str]] = set()
        for group in self.atomic_groups:
            for member in group.members:
                key = _reference_key(member)
                if key in group_members:
                    raise ValueError("atomic split groups must not overlap")
                group_members.add(key)
                assignment = assignment_by_reference.get(key)
                if assignment is None:
                    raise ValueError("atomic group member has no assignment")
                if assignment.atomic_group_id != group.group_id:
                    raise ValueError("assignment has the wrong atomic group ID")
                if assignment.split is not group.split:
                    raise ValueError("atomic group members must share one split")
        if group_members != set(assignment_by_reference):
            raise ValueError("atomic split groups must cover all assignments")
        observed_cross_split = sum(len(item.splits) > 1 for item in self.template_audit)
        if observed_cross_split != self.cross_split_template_count:
            raise ValueError("cross-split template count must match template audit")
        return self


class _DisjointSet:
    def __init__(self, size: int) -> None:
        self._parents = list(range(size))
        self._ranks = [0] * size

    def find(self, item: int) -> int:
        while self._parents[item] != item:
            self._parents[item] = self._parents[self._parents[item]]
            item = self._parents[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self._ranks[left_root] < self._ranks[right_root]:
            left_root, right_root = right_root, left_root
        self._parents[right_root] = left_root
        if self._ranks[left_root] == self._ranks[right_root]:
            self._ranks[left_root] += 1


def split_deduplicated_dataset(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    deduplication: DatasetDeduplicationResult,
    *,
    policy: DatasetSplitPolicy | None = None,
) -> DatasetSplitResult:
    """Split representatives while assigning every original record for audit."""

    effective_policy = policy or DatasetSplitPolicy()
    record_by_reference = _validate_inputs(records, deduplication)
    ordered_references = sorted(record_by_reference)
    index_by_reference = {
        reference: index for index, reference in enumerate(ordered_references)
    }
    disjoint_set = _DisjointSet(len(ordered_references))

    _connect_entity_groups(
        ordered_references,
        record_by_reference,
        index_by_reference,
        disjoint_set,
    )
    for cluster in deduplication.duplicate_clusters:
        cluster_indices = [
            index_by_reference[_reference_key(member)] for member in cluster.members
        ]
        anchor = cluster_indices[0]
        for member in cluster_indices[1:]:
            disjoint_set.union(anchor, member)

    component_indices: dict[int, list[int]] = defaultdict(list)
    for index in range(len(ordered_references)):
        component_indices[disjoint_set.find(index)].append(index)
    representative_references = {
        (record.source_id, record.record_id)
        for record in deduplication.unique_records
    }
    components = [
        _component_payload(
            indices,
            ordered_references,
            record_by_reference,
            representative_references,
        )
        for indices in component_indices.values()
    ]
    components.sort(
        key=lambda component: (
            component[3],
            component[2],
            component[0],
        )
    )
    minimum_groups = effective_policy.minimum_atomic_groups_per_split
    if len(components) < minimum_groups * 3:
        raise ValueError(
            "not enough isolated network/site groups to populate all three splits"
        )
    train_boundary, validation_boundary = _choose_boundaries(
        [component[4] for component in components],
        effective_policy,
    )
    component_splits = (
        [DatasetSplit.TRAIN] * train_boundary
        + [DatasetSplit.VALIDATION] * (validation_boundary - train_boundary)
        + [DatasetSplit.TEST] * (len(components) - validation_boundary)
    )

    split_by_reference: dict[tuple[str, str], DatasetSplit] = {}
    group_id_by_reference: dict[tuple[str, str], str] = {}
    atomic_groups: list[AtomicSplitGroup] = []
    for component, split in zip(components, component_splits, strict=True):
        group_id, references, first_capture, last_capture, representative_count = component
        for reference in references:
            split_by_reference[reference] = split
            group_id_by_reference[reference] = group_id
        atomic_groups.append(
            AtomicSplitGroup(
                group_id=group_id,
                split=split,
                members=tuple(
                    DatasetRecordReference(source_id=source_id, record_id=record_id)
                    for source_id, record_id in references
                ),
                representative_count=representative_count,
                first_captured_at=first_capture,
                last_captured_at=last_capture,
            )
        )

    assignments = tuple(
        DatasetSplitAssignment(
            record=DatasetRecordReference(source_id=source_id, record_id=record_id),
            split=split_by_reference[(source_id, record_id)],
            atomic_group_id=group_id_by_reference[(source_id, record_id)],
            network_id=record_by_reference[(source_id, record_id)].network_id,
            site_id=record_by_reference[(source_id, record_id)].site_id,
            device_id=record_by_reference[(source_id, record_id)].device_id,
            captured_at=record_by_reference[(source_id, record_id)].captured_at,
            is_representative=(source_id, record_id) in representative_references,
        )
        for source_id, record_id in ordered_references
    )
    _verify_entity_isolation(assignments, deduplication)
    partitions = _build_partitions(
        records=deduplication.unique_records,
        assignments=assignments,
        atomic_groups=tuple(atomic_groups),
        policy=effective_policy,
    )
    temporal_audit = _build_temporal_audit(partitions)
    if effective_policy.require_strict_temporal_order and not temporal_audit.strict_order:
        raise ValueError(
            "strict temporal order is impossible without splitting an isolated group"
        )
    template_audit = _build_template_audit(deduplication, split_by_reference)
    cross_split_template_count = sum(len(item.splits) > 1 for item in template_audit)
    limitations: list[str] = []
    if not temporal_audit.strict_order:
        limitations.append(
            "Entity-isolated groups overlap in capture time; allocation is ordered by "
            "each group's latest observation."
        )
    if cross_split_template_count:
        limitations.append(
            "Broad configuration templates span splits; template equality is not treated "
            "as device identity."
        )

    return DatasetSplitResult(
        policy=effective_policy,
        input_count=len(records),
        unique_count=len(deduplication.unique_records),
        cross_split_template_count=cross_split_template_count,
        assignments=assignments,
        atomic_groups=tuple(sorted(atomic_groups, key=lambda group: group.group_id)),
        partitions=partitions,
        template_audit=template_audit,
        temporal_audit=temporal_audit,
        limitations=tuple(limitations),
    )


def _validate_inputs(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    deduplication: DatasetDeduplicationResult,
) -> dict[tuple[str, str], ImportedDatasetRecord]:
    if len(records) < 3:
        raise ValueError("at least three sanitized records are required for splitting")
    record_by_reference = {
        (record.source_id, record.record_id): record for record in records
    }
    if len(record_by_reference) != len(records):
        raise ValueError("source_id and record_id pairs must be unique")
    fingerprint_by_reference = {
        _reference_key(fingerprint.record): fingerprint
        for fingerprint in deduplication.fingerprints
    }
    if set(record_by_reference) != set(fingerprint_by_reference):
        raise ValueError("records must exactly match the deduplication input")
    for reference, record in record_by_reference.items():
        fingerprint = fingerprint_by_reference[reference]
        if (
            record.raw_sha256 != fingerprint.raw_sha256
            or record.sanitized_sha256 != fingerprint.sanitized_sha256
        ):
            raise ValueError("record hashes do not match the deduplication result")
        if record.captured_at.tzinfo is None or record.captured_at.utcoffset() is None:
            raise ValueError("record capture times must include a timezone")
    return record_by_reference


def _connect_entity_groups(
    ordered_references: list[tuple[str, str]],
    records: dict[tuple[str, str], ImportedDatasetRecord],
    index_by_reference: dict[tuple[str, str], int],
    disjoint_set: _DisjointSet,
) -> None:
    for attribute in ("network_id", "site_id", "device_id"):
        buckets: dict[tuple[str, str], list[int]] = defaultdict(list)
        for reference in ordered_references:
            record = records[reference]
            value = getattr(record, attribute)
            if not isinstance(value, str):
                raise TypeError("dataset entity identifiers must be strings")
            buckets[(record.source_id, value)].append(index_by_reference[reference])
        for members in buckets.values():
            anchor = members[0]
            for member in members[1:]:
                disjoint_set.union(anchor, member)


def _component_payload(
    indices: list[int],
    ordered_references: list[tuple[str, str]],
    records: dict[tuple[str, str], ImportedDatasetRecord],
    representative_references: set[tuple[str, str]],
) -> tuple[str, tuple[tuple[str, str], ...], datetime, datetime, int]:
    references = tuple(sorted(ordered_references[index] for index in indices))
    captures = [records[reference].captured_at for reference in references]
    representative_count = sum(
        reference in representative_references for reference in references
    )
    if representative_count < 1:
        raise ValueError("every isolated component must contain a representative")
    public_references = tuple(
        DatasetRecordReference(source_id=source_id, record_id=record_id)
        for source_id, record_id in references
    )
    return (
        _atomic_group_id(public_references),
        references,
        min(captures),
        max(captures),
        representative_count,
    )


def _choose_boundaries(
    weights: list[int],
    policy: DatasetSplitPolicy,
) -> tuple[int, int]:
    prefix = [0]
    for weight in weights:
        prefix.append(prefix[-1] + weight)
    total = prefix[-1]
    train_target = total * policy.train_fraction
    validation_target = total * policy.validation_fraction
    test_target = total * policy.test_fraction
    minimum = policy.minimum_atomic_groups_per_split
    best: tuple[float, float, int, int] | None = None
    for train_boundary in range(minimum, len(weights) - 2 * minimum + 1):
        low = train_boundary + minimum
        high = len(weights) - minimum
        desired = (
            prefix[train_boundary] + validation_target,
            total - test_target,
        )
        candidates: set[int] = {low, high}
        for target in desired:
            position = bisect_left(prefix, target, lo=low, hi=high + 1)
            candidates.update({position - 1, position, position + 1})
        for validation_boundary in candidates:
            if validation_boundary < low or validation_boundary > high:
                continue
            train_count = prefix[train_boundary]
            validation_count = prefix[validation_boundary] - train_count
            test_count = total - prefix[validation_boundary]
            error = (
                abs(train_count - train_target)
                + abs(validation_count - validation_target)
                + abs(test_count - test_target)
            )
            score = (
                error,
                abs(train_count - train_target),
                train_boundary,
                validation_boundary,
            )
            if best is None or score < best:
                best = score
    if best is None:
        raise ValueError("unable to choose valid dataset split boundaries")
    return best[2], best[3]


def _verify_entity_isolation(
    assignments: tuple[DatasetSplitAssignment, ...],
    deduplication: DatasetDeduplicationResult,
) -> None:
    for attribute in ("network_id", "site_id", "device_id"):
        observed: dict[tuple[str, str], DatasetSplit] = {}
        for assignment in assignments:
            key = assignment.record.source_id, getattr(assignment, attribute)
            previous = observed.setdefault(key, assignment.split)
            if previous is not assignment.split:
                raise RuntimeError(f"{attribute} leaked across dataset splits")
    split_by_reference = {
        _reference_key(assignment.record): assignment.split
        for assignment in assignments
    }
    for cluster in deduplication.duplicate_clusters:
        splits = {split_by_reference[_reference_key(member)] for member in cluster.members}
        if len(splits) != 1:
            raise RuntimeError("duplicate cluster leaked across dataset splits")


def _build_partitions(
    *,
    records: tuple[ImportedDatasetRecord, ...],
    assignments: tuple[DatasetSplitAssignment, ...],
    atomic_groups: tuple[AtomicSplitGroup, ...],
    policy: DatasetSplitPolicy,
) -> tuple[DatasetPartition, ...]:
    assignment_by_reference = {
        _reference_key(assignment.record): assignment for assignment in assignments
    }
    partitions: list[DatasetPartition] = []
    target_fractions = {
        DatasetSplit.TRAIN: policy.train_fraction,
        DatasetSplit.VALIDATION: policy.validation_fraction,
        DatasetSplit.TEST: policy.test_fraction,
    }
    for split in DatasetSplit:
        split_assignments = [item for item in assignments if item.split is split]
        split_records = sorted(
            (
                record
                for record in records
                if assignment_by_reference[(record.source_id, record.record_id)].split
                is split
            ),
            key=lambda record: (record.source_id, record.record_id),
        )
        captures = [item.captured_at for item in split_assignments]
        partitions.append(
            DatasetPartition(
                split=split,
                target_fraction=target_fractions[split],
                actual_fraction=len(split_records) / len(records),
                source_record_count=len(split_assignments),
                atomic_group_count=sum(group.split is split for group in atomic_groups),
                network_count=len(
                    {
                        (item.record.source_id, item.network_id)
                        for item in split_assignments
                    }
                ),
                site_count=len(
                    {(item.record.source_id, item.site_id) for item in split_assignments}
                ),
                device_count=len(
                    {
                        (item.record.source_id, item.device_id)
                        for item in split_assignments
                    }
                ),
                first_captured_at=min(captures),
                last_captured_at=max(captures),
                records=tuple(split_records),
            )
        )
    return tuple(partitions)


def _build_temporal_audit(
    partitions: tuple[DatasetPartition, ...],
) -> TemporalSplitAudit:
    by_split = {partition.split: partition for partition in partitions}
    train = by_split[DatasetSplit.TRAIN]
    validation = by_split[DatasetSplit.VALIDATION]
    test = by_split[DatasetSplit.TEST]
    strict_order = (
        train.last_captured_at <= validation.first_captured_at
        and validation.last_captured_at <= test.first_captured_at
    )
    return TemporalSplitAudit(
        train_last_captured_at=train.last_captured_at,
        validation_first_captured_at=validation.first_captured_at,
        validation_last_captured_at=validation.last_captured_at,
        test_first_captured_at=test.first_captured_at,
        strict_order=strict_order,
    )


def _build_template_audit(
    deduplication: DatasetDeduplicationResult,
    split_by_reference: dict[tuple[str, str], DatasetSplit],
) -> tuple[TemplateSplitAudit, ...]:
    return tuple(
        TemplateSplitAudit(
            template_sha256=group.template_sha256,
            member_count=len(group.members),
            splits=frozenset(
                split_by_reference[_reference_key(member)] for member in group.members
            ),
        )
        for group in deduplication.template_groups
    )


def _reference_key(reference: DatasetRecordReference) -> tuple[str, str]:
    return reference.source_id, reference.record_id


def _atomic_group_id(references: tuple[DatasetRecordReference, ...]) -> str:
    payload = "\0".join(
        f"{reference.source_id}\0{reference.record_id}"
        for reference in sorted(references, key=_reference_key)
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"split-group-{digest}"
