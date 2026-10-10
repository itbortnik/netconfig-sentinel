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

The nine residual refusals carry six secret-keyword flags, two hostname flags
and one username flag. These are conservative scanner diagnoses, not nine
confirmed secret disclosures: later inspection found valueless/negated commands,
password authentication-order and other ambiguous contexts among them. They
remain excluded; this stage does not weaken checks to force acceptance.
Of the 411 parsed entries, 386 have unparsed units and 40 have
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

## Prefix-list follow-up

An explicit v3 preprocessing slice addresses Cisco prefix-list CIDR roles without
loosening v2 or repairing invalid source networks. A second private preflight
uses the same approved acquisition and a fresh ephemeral key. Paired v2/v3
execution within that run confirms all 422 previously sanitizable entries have
identical text and replacement counts; eight previously refused entries are now
sanitizable and pass the unchanged residual scanner/diagnostic parser.

The resulting 508-entry status distribution is 419 parsed, 74 sanitizer refusals,
nine residual refusals, two vendor-detection refusals, three text refusals and
one pending file review. Of the 419 parsed entries, 393 are partial and 40 have
warnings: 1,411 accepted / 3,788 unparsed / 5,199 command units. This is not
deduplicated size, improved detector accuracy or eight independent networks.
Bodies/keys remain unpersisted and imports/bundles/training remain zero. The
original v2 result above is retained as historical evidence, not overwritten.
The [v3 evidence](evaluation/owned-prefix-list-sanitization.json) separates owned
functional round trips from actual upstream content diagnostics.

## Stricter residual-content follow-up

The per-occurrence scanner in `dataset-quality-0.3.0` closes an authored
mixed-redaction bypass; it does not loosen refusals to increase corpus size.
A third append-only local preflight, still using sanitizer v3 and the approved
pinned acquisition, now yields 413 parsed / 74 sanitizer refusals / 15 residual
refusals / two vendor-detection refusals / three text refusals / one file hold.
Six entries previously admitted to diagnostic parsing are additionally withheld.
These are recognized keyword/content flags, not six confirmed secret disclosures.

The final scanner also recognizes the already supported, actually redacted
`pre-shared-key ascii-text` value instead of falsely refusing its qualifier.
Two of those six inputs return to diagnostics: final counts are 415 parsed,
74 sanitizer refusals, 13 residual refusals, two vendor-detection refusals,
three text refusals and one hold. Of 415 parsed entries, 389 are partial and
40 have warnings: 1,387 accepted / 3,738 unparsed / 5,125 command units.
An ASCII value before the marker, including a numeric value, is still refused.
Earlier strict results and the corrected final run are retained separately.

Of the intermediate 413 parsed entries, 387 were partial and 40 had warnings: 1,384 accepted /
3,697 unparsed / 5,081 command units. Both older preflights remain untouched.
Physical/capture metadata remain unknown, sanitized bodies/keys are not stored,
and imports/bundles/training remain zero. [Residual-gate evidence](evaluation/owned-residual-content-gate.json)
records the stricter scope and historical compatibility separately from v3 CIDR
qualification or independent data/model quality.

## Explicit unknown-metadata fixture intake

The next local run uses `source-fixture-1.0` and the existing reviewed local
importer, not invented physical entity IDs or capture dates. It selects the 415
entries that passed the final preflight, rechecks approved acquisition/approval/
file SHA-256 evidence, imports with explicit sanitizer v3 and applies current
residual checks. The held entries are not implicitly approved or reintroduced.

Imported fixture records keep network/site/device/capture/role `null`, acquisition
in `source_collected_at`, and one conservative collection grouping. Ordinary
manifest `1.0` remains unchanged. Source permission for training is not a
training run or proof of a healthy parent. The same content deduplicator finds
415 representatives, zero exact/near links and 412 broad templates; bounded
candidate discovery does not guarantee exhaustive near-match recall.

All 415 reparse with the same diagnostic counts: 389 partial, 40 warning-bearing,
1,387 accepted / 3,738 unparsed / 5,125 command units. Lossless segmentation
accepts 412 representatives and yields 3,445 structural blocks; three malformed
JunOS structures are refused independently. The lexical approximation counts
30,819 tokens over representatives, not model-tokenizer tokens. The initial
private intake attempt left an explicit incomplete marker after a segmentation
refusal; subsequent runs preserve that attempt and record refusals rather than
assuming every parser-accepted configuration is segmentable.

Only local private staging contains sanitized fixture bodies and reviewed raw
blob links. No configurations or keys are published. This staging is not the
quality-gated split artifact format. The observed splitter/quality metrics/
artifact writer/current mutation lineage refuse fixture records before creating
any corpus or target. Independent networks, capture-time measurements and
confirmed-real labels remain missing (`null`). No train/validation/test partitions,
model training, selection or calibration have been run on this source. A reviewed
train-only exposure protocol remains the next integration boundary.

[Owned intake evidence](evaluation/owned-source-fixture-intake.json) records the
actual source run, installed-package replay and unchanged historical contracts.
