# Dataset ingestion

Dataset candidates cross an explicit review and sanitization boundary before
they can reach parsing, feature extraction, or model training. This slice only
imports local files. It does not download repositories or claim that a
production dataset has been assembled.
The [approved pinned-source intake](dataset-source-review.md) records human
authorization, exact local acquisition and content preflight. Its upstream
fixtures still have unknown device-capture/entity metadata. The explicit fixture
intake below now imports local reviewed candidates without fabricating those
fields; no quality-gated split corpus or model training is claimed.

## Source manifest

Every import uses one versioned JSON manifest. The source section records the
origin, source class, license or authorization identifier, review status,
allowed uses, and collection time. Real configurations additionally require an
authorization reference. Import stops unless the review status is `approved`
and the requested use appears in `allowed_uses`.

```json
{
  "schema_version": "1.0",
  "source": {
    "source_id": "lab-routers-2026-09",
    "source_type": "lab",
    "origin": "controlled isolated lab",
    "license_id": "INTERNAL-LAB-AUTHORIZATION-2026-09",
    "license_url": null,
    "license_review": "approved",
    "allowed_uses": ["training", "evaluation"],
    "collected_at": "2026-09-18T00:00:00Z",
    "authorization_reference": null
  },
  "records": [
    {
      "record_id": "lab-edge-01",
      "relative_path": "configs/lab-edge-01.cfg",
      "network_id": "lab-topology-a",
      "site_id": "lab-site-a",
      "device_id": "lab-edge-01",
      "captured_at": "2026-09-18T00:00:00Z",
      "vendor_hint": "cisco",
      "device_role": "edge-router",
      "expected_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

The values above illustrate the schema; they are not evidence that a source
has been reviewed. A reviewer must verify the actual license, authorization,
and permitted uses before changing a source to `approved`.

Allowed source classes are `open_repository`, `batfish_test`, `lab`,
`generated`, and `authorized_real`. Allowed uses are `research`, `training`,
`evaluation`, `redistribution`, and `derivative_works`. A use is never inferred
from the source class.

## Import boundary

`load_dataset_manifest` accepts bounded UTF-8 JSON and rejects unknown fields.
`import_local_dataset` then enforces the following controls:

- paths must be POSIX-style relative paths under the selected root;
- symbolic links and extensions outside `.cfg`, `.conf`, and `.txt` are
  rejected;
- each file is read with a fixed upper bound of 1 MiB by default;
- empty files, control bytes, invalid UTF-8, and SHA-256 mismatches are
  rejected;
- raw bytes are sanitized in memory and are never included in the return
  model.

The optional expected hash should be present for reviewed sources. It binds the
manifest decision to the exact bytes that were reviewed.

```python
import os
from pathlib import Path

from ml.datasets import DatasetUse, import_local_dataset, load_dataset_manifest

manifest = load_dataset_manifest(Path("manifest.json"))
records = import_local_dataset(
    manifest,
    root=Path("reviewed-source"),
    intended_use=DatasetUse.TRAINING,
    pseudonymization_key=os.environ["DATASET_PSEUDONYMIZATION_KEY"].encode(),
)
```

The pseudonymization key must contain at least 16 bytes and must be supplied at
runtime from secret storage. It must not be committed with a manifest.

## Explicit unknown-metadata fixture intake

The historical `DatasetManifest` schema `1.0` and its loader remain strict:
they require actual declared network/site/device identifiers and an aware
device-capture timestamp. Do not invent these fields for upstream parser fixtures
or substitute a repository commit/acquisition time for a device observation.

`DatasetFixtureManifest` schema `source-fixture-1.0` is an explicit alternative
for `batfish_test`, `open_repository` or `generated` **source fixtures**, not
real/lab observations. `DatasetFixtureRecord` requires a reviewed SHA-256 and
safe local path. Network, site, device, capture time and role are `null`; invented
values, labels and unknown fields are rejected. `load_dataset_fixture_manifest`
uses the same bounded text boundary without relaxing `load_dataset_manifest`.

The same `import_local_dataset` implementation enforces source review, permitted
use, local path/symlink/extension/size/text/hash checks and in-memory sanitization.
For this explicit route it additionally revalidates the manifest and applies
current residual-content checks before returning any result. A failure refuses
the import rather than silently accepting the other records in that manifest.

Returned `ImportedDatasetFixtureRecord` values preserve the four unknown entity/
capture fields and role as `null`. `source_collected_at` records acquisition,
not device capture. `collection_group_id` is a pseudonymous conservative source
collection grouping, **not** a physical network, device or independent sample.
All records from the same source ID use one unknown-collection sanitization
scope/group; different source IDs must not be used to split one collection into
purported independent networks. No record-level ground-truth label is inferred.

```python
from ml.datasets import DatasetUse, import_local_dataset, load_dataset_fixture_manifest
from ml.preprocessing import SanitizationPolicy

manifest = load_dataset_fixture_manifest(manifest_path)
fixtures = import_local_dataset(
    manifest, root=reviewed_source_root, intended_use=DatasetUse.TRAINING,
    pseudonymization_key=runtime_secret_key,
    sanitization_policy=SanitizationPolicy(version="config-sanitizer-0.3.0"),
)
```

`intended_use=training` checks the source permission; it does not create a
training-ready corpus. Content deduplication and lossless segmentation can
consume these records. The observed-corpus splitter, full quality metrics,
split-artifact writer and current mutation-lineage contract refuse this record
kind. A dedicated reviewed train-only exposure protocol is still required before
using unknown-metadata fixtures in model selection/calibration workflows. Parser
acceptance is not a healthy label or vendor syntax qualification; segmentation
may independently refuse malformed structures. The actual pinned-source local
run and its limits are recorded in
[owned fixture-intake evidence](evaluation/owned-source-fixture-intake.json).

## Sanitization

The historical default `config-sanitizer-0.1.0` replaces or pseudonymizes:

- Cisco IOS and JunOS hostnames, usernames, domain names, and contacts;
- SNMP communities, passwords, password hashes, shared secrets, and key
  strings;
- private-key and certificate block contents;
- IPv4 and IPv6 addresses when the reviewed policy enables it;
- manifest network, site, device, and record identifiers in imported output.

Aliases are HMAC-derived and no reversible mapping is returned. The scope
combines the source and topology, preserving equality and IP prefix structure
inside one topology while separating unrelated sources. Addresses with
protocol meaning, including unspecified, loopback, multicast, link-local, and
IPv4 masks or wildcards, remain unchanged.

Common-prefix preservation does **not** preserve zero host bits of a network
address. A live owned experiment found that v1 could turn a valid JunOS static
route into a noncanonical CIDR. Do not use v1 output as evidence of equivalent
routing semantics. Existing artifacts, training/inference defaults and hashes
are not silently regenerated or promoted by this correction.

Explicit `SanitizationPolicy(version="config-sanitizer-0.2.0")` qualifies a
bounded CIDR slice: `route`, `route-filter`, `network`, `aggregate-address`,
`source-address`, `destination-address`, and inline `prefix-list NAME` network
roles. It masks the transformed network's host bits, while explicit `address`
or `ipv6 address` interface roles and bare next-hop/peer hosts retain the same
address permutation. Invalid source networks and unknown CIDR roles are refused
with a generic error; bare hierarchical prefix-list items and separate IPv4
network/mask commands are not supported by this slice. It does not guarantee
arbitrary vendor syntax, reserved-address class preservation, or full topology
equivalence. Retained protocol-special addresses have the historical exceptions.

Pass this policy through `import_local_dataset(..., sanitization_policy=policy)`.
Segmentation and mutation accept all three known versions, without resanitizing an
existing record. The dataset quality policy still defaults to v1 for historical
reproducibility: explicitly select the intended `allowed_sanitization_versions`
when reviewing v2 data. A persisted bundle requires one sanitization version;
do not silently mix versions or reuse a model's old evaluation claims. Query
destinations must be transformed with the same version/key/topology as inputs.

Explicit `SanitizationPolicy(version="config-sanitizer-0.3.0")` adds a bounded
IOS/IOS-XE prefix-list CIDR role to v2. It accepts positive `ip|ipv6 prefix-list
NAME [seq NUMBER] permit|deny NETWORK/LENGTH [ge N] [le N]` lines with a bounded
ASCII identifier, optional sequence 1..4,294,967,294, canonical source network,
matching address family and valid ordered prefix-length bounds. `ge` must exceed
the base length; `le` cannot be shorter, `ge <= le`, and both are family-bounded.
Entry action, sequence, order, bounds, indentation and line endings are retained.
The network alias uses the same host permutation, then clears network host bits.
The qualification follows the official [IOS-XE IPv4 reference](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/release/17-17/command_reference/b_1717_9600_cr/ip_routing_commands.html)
and [IOS IPv6 reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6/command/ipv6-cr-book/ipv6-i4.html).
This conservative slice is not a vendor syntax validator: negative forms,
CIDR-bearing descriptions/comments, duplicate/reversed bounds, unknown suffixes,
mixed-family entries, bare JunOS hierarchy and separate IPv4 masks remain
unqualified/refused. An explicit no-IP policy still disables IP preprocessing;
it is not anonymous data. v1 default/output and explicit v2 output/refusals stay
unchanged. The full quality gate must explicitly allow v3; old corpora/model
claims are not migrated. [Local pinned-source diagnostics](dataset-source-review.md#prefix-list-follow-up)
measure eight additional accepted entries, not independent data quality.

Sanitization is a defense-in-depth preprocessing step, not proof that arbitrary
vendor syntax contains no identifying data. New vendors and syntax require
dedicated fixtures and reviewer sampling before operational ingestion. The
next boundary applies the exact and near-duplicate handling described in
[`dataset-deduplication.md`](dataset-deduplication.md), followed by the isolated
partitioning described in [`dataset-splitting.md`](dataset-splitting.md). The
result then crosses the quality gate in
[`dataset-quality.md`](dataset-quality.md) before it can be written in the
format described by [`dataset-artifacts.md`](dataset-artifacts.md).
