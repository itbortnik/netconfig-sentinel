# Dataset deduplication

Deduplication runs only on `ImportedDatasetRecord` values after source review
and sanitization. It returns one deterministic representative per duplicate
component together with fingerprints, direct match evidence, and template
groups. It does not delete local source files or claim that candidate files are
independent configurations.

## Matching stages

Version `dataset-dedup-0.1.0` applies evidence in descending order of strength:

1. identical SHA-256 of the original reviewed bytes;
2. identical SHA-256 of sanitized text;
3. identical SHA-256 after deterministic formatting normalization;
4. exact Jaccard similarity of normalized line and adjacent-line tokens after
   MinHash/LSH candidate discovery.

Formatting normalization removes blank and comment-only lines, removes block
comments, applies Unicode NFKC and case folding, collapses whitespace, and
normalizes spacing around structural punctuation. It preserves command order
and configured values.

The default near-duplicate threshold is `0.82`. MinHash uses 64 deterministic
permutations split into eight LSH bands. Template and stable device identity
buckets provide additional candidates. Each bucket compares a bounded number
of candidates so one common template cannot create an unbounded quadratic
comparison. The bound is part of the recorded policy.

MinHash is only a retrieval optimization. A pair is connected only after exact
Jaccard similarity meets the configured threshold. Accepted links form a
spanning tree, so a transitive cluster can contain two endpoints whose direct
similarity is below the threshold; the intermediate verified links remain in
the result for audit.

## Template groups

Template text additionally abstracts sanitized pseudonyms, IP addresses,
quoted literals, long hexadecimal values, and numbers. Its SHA-256 groups
configurations generated from the same broad structure.

Template equality alone never marks records as duplicates. Two routers may
share a valid standard template while representing independent devices and
networks. Template groups are intended for diversity reporting, candidate
blocking, and later split diagnostics.

## Representatives and counts

The representative of each connected duplicate component is selected by the
earliest capture time, then source ID, record ID, and sanitized hash. This rule
is independent of input order. Original member references and match links stay
in `duplicate_clusters`; no reversible identity data or configuration text is
added to the audit structures.

Reported counts have precise meanings:

- `input_count` is the number of sanitized candidates;
- `unique_count` is the number of connected components and equals the number
  of returned representatives;
- `exact_duplicate_count` is the number of accepted spanning-tree links based
  on one of the three exact hashes;
- `near_duplicate_count` is the number of accepted similarity links;
- `template_group_count` is the number of distinct template hashes, including
  templates represented by one record.

These counts always satisfy:

```text
unique_count + exact_duplicate_count + near_duplicate_count = input_count
```

Candidate-file count is not a dataset-size metric. Operational reporting must
use the unique count alongside independent network, site, role, block, token,
and confirmed-anomaly counts.

## Usage

```python
from ml.datasets import DatasetUse, deduplicate_dataset, import_local_dataset

sanitized = import_local_dataset(
    manifest,
    root=source_root,
    intended_use=DatasetUse.TRAINING,
    pseudonymization_key=pseudonymization_key,
)
result = deduplicate_dataset(sanitized)

training_candidates = result.unique_records
audit_clusters = result.duplicate_clusters
```

Duplicate clusters must remain indivisible during later train, validation, and
test assignment. If a workflow deliberately retains multiple versions, it
must group by cluster, network, site, device, and capture time so closely
related configurations cannot leak across splits.

The implemented splitter and its temporal audit are described in
[`dataset-splitting.md`](dataset-splitting.md).

The default threshold and LSH recall require evaluation on representative
corpora. Raising the candidate bound may improve recall at additional compute
cost. Threshold changes are explicit policy changes and must be recorded with
derived artifacts.
