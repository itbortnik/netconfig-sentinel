# Dataset ingestion

Dataset candidates cross an explicit review and sanitization boundary before
they can reach parsing, feature extraction, or model training. This slice only
imports local files. It does not download repositories or claim that a
production dataset has been assembled.

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

## Sanitization

Sanitizer version `config-sanitizer-0.1.0` replaces or pseudonymizes:

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

Sanitization is a defense-in-depth preprocessing step, not proof that arbitrary
vendor syntax contains no identifying data. New vendors and syntax require
dedicated fixtures and reviewer sampling before operational ingestion. The
next dataset stages add exact and near-duplicate handling, split isolation,
quality reports, and immutable sanitized storage.
