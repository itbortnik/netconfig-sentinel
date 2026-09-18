# Dataset splitting

Training, validation, and test sets are created only after sanitization and
deduplication. Splitter version `dataset-split-0.1.0` consumes both the complete
sanitized input and its matching `DatasetDeduplicationResult`. It rejects
missing records, extra records, changed hashes, duplicate references, and
timezone-free capture timestamps.

## Isolation boundary

The splitter constructs a transitive closure over four relationships:

- records from the same source-scoped network;
- records from the same source-scoped site;
- versions of the same source-scoped device;
- all members of a duplicate cluster, including cross-network duplicates.

Each connected component becomes an `AtomicSplitGroup`. It is always assigned
as one unit. Consequently, a network, site, device history, or exact/near-copy
family cannot occur in two partitions. Every test network and test site is
therefore absent from training under the recorded pseudonymous identities,
which is stricter than a 20% unseen-topology target.

The source scope prevents an accidental collision between independently
collected identifiers from merging unrelated sources. Duplicate evidence can
still intentionally connect records across sources.

## Chronological allocation

Atomic groups are ordered by their latest capture timestamp, then their first
timestamp and deterministic group ID. Contiguous groups are allocated to
train, validation, and test. Target ratios are optimized over the number of
deduplicated representatives, not candidate-file count.

The defaults are:

- train: 70%;
- validation: 15%;
- test: 15%;
- at least one atomic group in every partition.

Indivisible groups can make exact ratios impossible. Each partition therefore
records both target and actual fractions, source-record count, unique
representatives, atomic groups, networks, sites, devices, and capture range.

A long-lived network may contain an early and a late observation. Keeping that
network isolated can make its time range overlap another partition even though
groups are allocated chronologically. `TemporalSplitAudit.strict_order`
reports whether these conditions both hold:

```text
train.max_time <= validation.min_time
validation.max_time <= test.min_time
```

By default the overlap is retained as an explicit limitation because silently
splitting a network would create entity leakage. Setting
`require_strict_temporal_order=True` rejects such a dataset instead, allowing a
reviewer to change the collection window or quarantine the spanning group.

## Template audit

Broad template equality is not identity. Standardized configurations from
independent networks may legitimately appear in different partitions. Every
repeated template therefore receives a `TemplateSplitAudit` that lists the
partitions it spans. This supports later diversity and contamination review
without forcing a potentially huge template family into one partition.

## Usage

```python
from ml.datasets import (
    DatasetSplit,
    deduplicate_dataset,
    split_deduplicated_dataset,
)

deduplicated = deduplicate_dataset(sanitized_records)
split_result = split_deduplicated_dataset(
    sanitized_records,
    deduplicated,
)

partitions = {item.split: item.records for item in split_result.partitions}
training_records = partitions[DatasetSplit.TRAIN]
validation_records = partitions[DatasetSplit.VALIDATION]
test_records = partitions[DatasetSplit.TEST]
```

`DatasetPartition.records` contains only deduplicated representatives.
`DatasetSplitResult.assignments` contains every original sanitized candidate,
including removed duplicates, so lineage and leakage checks remain auditable.
No ratios or counts produced from fixtures are presented as production dataset
metrics.

The split result is not persisted directly. It first enters the quality gate
described in [`dataset-quality.md`](dataset-quality.md); only a report without
blocking issues may be written as the sanitized artifact described in
[`dataset-artifacts.md`](dataset-artifacts.md).
