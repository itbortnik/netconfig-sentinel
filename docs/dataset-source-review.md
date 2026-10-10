# Approved local public-source intake

The human user approved the pinned Batfish source on 2026-10-10 for local
research, training, evaluation and derivative preprocessing, subject to
file-level exception checks. Redistribution of configuration bodies was not
requested or authorized. This supersedes the earlier pending metadata proposal;
it is not an approved full dataset, a training run or legal/privacy qualification
of every file. The existing importer and full quality gate remain in force.

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

These are 379,872 bytes of extensionless candidate entries, **not** 508
independent networks or confirmed anomalies. After approval, all entries were
acquired locally and verified against their pinned Git blob, byte count and
SHA-256. There are 507 distinct raw blobs. The root license is retained locally;
no raw or sanitized configuration bodies are published in this repository.

## Local content preflight

A bounded notice heuristic flagged three entries: two are also invalid UTF-8;
the remaining JunOS quote-bug fixture contains a `license` configuration
statement, not a demonstrated third-party legal override. It remains excluded
pending sensitive-content/provenance review. The heuristic is not a legal scan.
Two invalid-encoding inputs and one control-byte input are excluded separately.
Approval does not authorize separately supplied customer data or waive per-file
checks, attribution or license notices.

The actual preflight applies explicit sanitizer `config-sanitizer-0.2.0`, then
the shared `scan_sanitized_content` quality checks before diagnostic parsing.
It never falls back to historical v1. A single ephemeral pseudonymization key
and conservative unknown-topology scope were used in memory; neither the key nor
sanitized bodies were saved. Private diagnostics retain hashes/codes/counts,
not raw error messages or sensitive values. This run is not a durable corpus.

| Final status (one per candidate entry) | Entries |
| --- | ---: |
| Parsed for content diagnostics | 411 |
| Sanitizer refused unsupported/invalid context | 82 |
| Residual recognized sensitive content refused | 9 |
| Parser refused | 2 |
| Invalid encoding/control text refused | 3 |
| File-level content review pending | 1 |
| Total | 508 |

The nine residual refusals include six credential directives, two hostnames and
one username. Of the 411 parsed entries, 386 have unparsed units and 40 have
warnings. The coverage denominator is 5,022 command units: 1,358 accepted and
3,664 unparsed. These are adapter diagnostics, not vendor syntax qualification,
deduplicated size or detector accuracy. Directory hints did not conflict with
detected vendors in accepted diagnostics.

## Remaining import boundary

Physical network/site/device/role and device-capture times are unknown. They are
not inferred from filenames or replaced by the acquisition timestamp. The
collection remains conservatively unsplit; it cannot establish three independent
train/validation/test groups. The current record contract requires capture and
entity metadata, so no `ImportedDatasetRecord`, split or dataset bundle was
created. Independent-network and real-confirmed anomaly counts remain missing,
not zero. Deduplication, model training, calibration, selection and independent
evaluation were not run on this collection. A metadata-aware import path and
reviewed representative inputs are still needed; full quality gates must not be
bypassed. The minimized [evidence](evaluation/owned-batfish-source-intake.json)
binds private acquisition/preflight/check artifacts without distributing bodies.

Upstream parser fixtures can contain intentionally invalid or incomplete input.
Do not label every original healthy or convert parse warnings into anomaly
ground truth. They may support parser robustness and reviewed training inputs,
but do not supply real-confirmed labels, independent real calibration/test
cohorts, or proof of unknown external pretraining exposure.
