# Pending public-source intake

This is a source-review proposal, not an approved dataset or a training run.
The existing `DatasetSource.license_review` gate requires human review before
`import_local_dataset` can accept a new source. Public availability and a
repository license alone do not mark individual records reviewed or establish
labels, independent networks, capture times, privacy, or model quality.

## Fixed Batfish candidate

Metadata was inspected at upstream revision
`329c14bf712f81b1522147abb00419c8e34e8f4a`, not a moving branch. The exact
[root license](https://github.com/batfish/batfish/blob/329c14bf712f81b1522147abb00419c8e34e8f4a/LICENSE)
contains Apache-2.0, is 11,357 bytes, and was checked against Git blob
`261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64` and SHA-256
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
The complete nontruncated Git tree contains no additional license/notice files
under the selected grammar resource directories. This metadata observation is
not a final legal or per-file provenance determination.

| Directory under `projects/batfish/src/test/resources/org/batfish/grammar/` | Candidate entries |
| --- | ---: |
| `cisco/testconfigs/` | 169 |
| `juniper/testconfigs/` | 339 |
| Total after excluding two `BUILD.bazel` files | 508 |

These are 379,872 bytes of extensionless candidate blobs, **not** 508 reviewed
supported configurations, independent networks, or confirmed anomalies. No
configuration body has been downloaded by this intake step. Only tree/license
metadata was read; no import, sanitization, deduplication, splitting, training,
model selection, or evaluation was performed. Status remains `pending`.

## Review decision needed

A human reviewer must approve the selected source and intended local research,
training/evaluation and derivative preprocessing uses, or reject/restrict them.
The proposed intake does not redistribute raw or sanitized configuration bodies
on the public repository. Review must preserve applicable attribution/license
notices and check any file-level exceptions before accepting a record. It does
not replace authorization for separately supplied real customer configurations.

After approval, use the existing importer/quality/artifact contracts rather than
another ingestion pipeline: verify each pinned blob and content hash, apply
bounded text checks and reviewed sanitization, retain unsupported/rejected counts,
deduplicate before counting, and keep derived views with their source families.
The new CIDR policy has explicit unsupported contexts: never silently fall back
to historical v1 to force acceptance. Directory/vendor hints are not device
qualification. Unknown physical network/site/role/time metadata must not be
invented; keep grouping conservative and document fixture revision/acquisition
time separately from real device capture time.

Upstream parser fixtures can contain intentionally invalid or incomplete input.
Do not label every original healthy or convert parse warnings into anomaly
ground truth. They may support parser robustness and reviewed training inputs,
but do not supply real-confirmed labels, independent real calibration/test
cohorts, or proof of unknown external pretraining exposure.
