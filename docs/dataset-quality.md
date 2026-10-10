# Dataset quality report

The quality report is the gate between isolated dataset splitting and durable
sanitized storage. New report version `dataset-quality-0.3.0` recomputes checks from
the sanitized records, the deduplication result, the split result, and the
reviewed source objects. It does not accept counts supplied in a separate
spreadsheet or infer that a target has been reached.

## Pipeline binding

`build_dataset_quality_report` first verifies that the sanitized input has the
same unique record references as both the deduplication fingerprints and split
assignments. It then creates a SHA-256 pipeline fingerprint over:

- every source and record reference plus its raw and sanitized hashes;
- deduplication and splitting algorithm versions and policies;
- every split assignment, atomic group, and representative flag.

The artifact writer recomputes this fingerprint. A report from another run,
different records, or a changed policy cannot authorize persistence.

## Blocking checks

A blocking issue makes `technically_valid` false and prevents artifact writing.
The current report checks:

- source provenance exists, review is approved, and the intended use is
  explicitly allowed;
- the stored sanitized SHA-256 matches the text and the sanitizer version is
  allowed by policy;
- text is non-empty and contains no forbidden control characters;
- sanitizer aliases have the required pseudonymous form;
- no unredacted password, shared key, SNMP community, certificate, private-key
  material, hostname, username, domain, or contact is recognized;
- the required fraction of test networks and sites is absent from training.

The residual-content scanner is defense in depth, not proof that all possible
vendor syntax is anonymous. Adding a vendor or command family requires new
sanitizer fixtures and reviewer sampling.

`scan_sanitized_content(text, sanitized_sha256=..., sanitization_version=...,
allowed_versions=...)` exposes these same content/hash/version checks before
physical entity or device-capture metadata is available. It returns immutable,
sorted unique `(code, generic_message)` pairs without content values. The full
record gate delegates to this scanner; historical serialized reports remain
readable without rewriting, and the default allowed sanitizer is still v1.
An empty result is not source approval, a privacy guarantee, an import, a split
or permission to persist/train. Explicitly allow v2/v3 when reviewing that content.
The caller must enforce the
existing acquisition size/text bounds and independently review file provenance.

## Per-occurrence checks and historical reports

Version 0.3 checks every recognized credential, community, identity and contact
occurrence independently. A redaction marker elsewhere on a line no longer
exempts an unredacted value, and a password-policy directive exempts only itself.
Credential placeholders may follow a qualified one-digit encoding selector;
community/contact placeholders cannot hide a numeric value. Placeholder suffixes,
wrong PEM closing labels, nested/orphan boundaries and extra PEM material are
refused with generic diagnostics. Repeated markers are scanned using ordered
spans/token offsets rather than a quadratic exemption search.
The already supported `pre-shared-key ascii-text <redacted-secret>` qualifier
is recognized explicitly; the marker must still be the actual ASCII value.

Readers continue to accept `dataset-quality-0.2.0` and 0.3 payloads, preserving
their recorded version. Reading an old artifact performs its existing integrity
verification, not automatic privacy recertification or rewriting of stored data.
New report construction emits 0.3. Before any new artifact directory is created,
the writer runs current content/hash/version checks over every input, even if
supplied with a structurally valid hash-bound historical report. A previous
report is not authority to persist newly recognized unsafe content. Sanitized
bytes, old report/manifest hashes and model histories are not regenerated.

The [owned check evidence](evaluation/owned-residual-content-gate.json) separates
authored bypass regressions, a real artifact written by the old installed runtime,
and the stricter approved-source preflight. Recognized flags can still include
benign/ambiguous or unsupported syntax; this conservative scanner is not a full
vendor-aware secret detector or a privacy guarantee.

## Warnings and distributions

Warnings preserve limitations without weakening entity isolation. They cover
overlapping capture-time ranges, train/validation/test fractions that differ
materially from policy targets because groups are indivisible, and excessive
concentration of one device role once the corpus is large enough for that
check. Vendor and role distributions are calculated over deduplicated
representatives and include an explicit `unknown` bucket.

Defaults require at least 20% unseen test networks and sites, allow a five
percentage-point partition deviation, and warn when one role exceeds 50% in a
corpus of at least 20 unique configurations. The complete policy is embedded
in every report.

## Scale readiness

The report compares observed values with these minimum PoC targets:

| Metric | Minimum |
| --- | ---: |
| Candidate configurations | 5,000 |
| Unique configurations after deduplication | 1,000 |
| Independent networks | 10 |
| Configuration blocks | 10,000 |
| Tokens | 10,000,000 |
| Synthetic labeled anomalies | 10,000 |
| Human-confirmed anomalies | 50 |
| Isolated test networks | 5 |

`poc_scale_ready` becomes true only when every target is met. It is independent
of `technically_valid`: a small clean fixture can be technically valid without
being PoC-scale, while a large corpus with a blocking privacy issue cannot be
persisted.

Configuration blocks use a deterministic structural approximation: top-level
Cisco commands or stanzas, top-level JunOS stanza starts, and JunOS `set`
commands grouped by their first three tokens. Blank and comment delimiters
reset the active group. Tokens use the report's versioned lexical
approximation. These are reproducible corpus metrics, not model-specific
tokenizer counts.
The synthetic count is derived from unique generated samples with
`count_synthetic_anomaly_labels`; linked mutations count as separate labels.
The confirmed-anomaly value is supplied from a separately reviewed labeling
process and is never inferred from parser errors, detector output, or synthetic
labels.

## Usage

```python
from ml.datasets import DatasetUse, build_dataset_quality_report
from ml.mutation import count_synthetic_anomaly_labels

report = build_dataset_quality_report(
    sanitized_records,
    deduplication_result,
    split_result,
    sources=reviewed_sources,
    intended_use=DatasetUse.TRAINING,
    synthetic_anomaly_count=count_synthetic_anomaly_labels(mutation_samples),
    confirmed_anomaly_count=confirmed_anomalies,
)

if not report.technically_valid:
    raise RuntimeError("dataset has blocking quality issues")
```

The next boundary and on-disk structure are described in
[`dataset-artifacts.md`](dataset-artifacts.md).
