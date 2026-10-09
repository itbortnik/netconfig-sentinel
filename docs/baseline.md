# Peer-group baseline

The peer baseline detects normalized configuration values that differ from a
well-defined group of comparable devices. It is deterministic and does not
replace policy checks: a common configuration can still violate policy, while
a secure but unusual configuration can still require review.

The sections below describe released `peer-baseline-0.1.0`, including the
persistent API. [Expanded 0.2.0 local comparisons](expanded-comparisons.md) are
an explicit separate selection; historical profiles keep their original meaning.

## Group identity

A peer group uses the complete key:

```text
vendor + platform + device_role + site_class + service_profile
```

All five values must be present before a baseline can be built or evaluated.
The caller is responsible for assigning trustworthy inventory metadata; parser
inference is intentionally not used for role, site class, or service profile.
A profile requires at least three configurations by default.

## Exact consensus features

The first profile version compares exact canonical values for:

- SSH, Telnet, AAA, SNMP, NTP, and Syslog state;
- VLAN identifiers and names;
- ordered ACL rule patterns without device-local ACL names or sequence numbers;
- BGP presence and local AS;
- OSPF presence and area membership;
- static-route destination sets.

Only values supported by at least 75% of the peers are retained by default.
Every finding records the supporting and total peer counts, the observed and
expected normalized values, source provenance where available, and the profile
version. A feature without consensus is omitted instead of being guessed.

## Unsupported syntax ratio

In historical peer 0.1/0.2, the parser-confidence deficit
(`1 - parser_confidence`) is compared with the
peer median plus a configurable tolerance of five percentage points. A finding
includes every preserved unsupported source line. This is a triage signal: it
does not prove that an unsupported statement is unsafe.

## Limitations

- Exact set comparison does not yet understand equivalent policy intent.
- Inventory labels and the selected peer population can bias the result.
- The standalone builder returns an in-memory profile. The opt-in
  [persistent API](api-comparisons.md) stores the exact profile and selected
  input IDs/hashes inside the encrypted analysis; it excludes the target device,
  duplicate device versions and snapshots received after the target.
  There is no automatic inventory inference, profile registry or refresh.
- Peer agreement is not evidence of compliance and cannot reduce the severity
  of a deterministic policy finding.

## Expanded peer templates

`peer-baseline-0.2.0` compares 19 supported exact-consensus features using 3–20
explicit, completely parsed sources with the full five-field group key. Distinct
declared hostnames/source hashes and non-future collection dates are anti-copy
and time-binding guards, not independent device identity or trusted history.
Management compares actual server sets; interfaces/users, VLAN/ACL/prefix-list
templates and BGP/OSPF/static-route parameters go beyond presence-only checks.
Individual router IDs, interface/neighbor addresses and object labels are omitted
from role templates; supported parameter values, ordering and multiplicity are
retained. Static-route addressing and NTP/Syslog servers remain exact design
values. No semantic equivalence, effective defaults or topology are inferred.

The profile pins each source/date and records both retained and omitted fields,
support counts and thresholds. Partial current parsing skips every property
comparison and only permits parser-confidence-deficit triage. Its report is
explicitly partial even when findings are empty. Peer consensus is not an
approved security baseline and scores are not calibrated fault probabilities.
No policy, model, network or device validation/application is implied. This
version is explicitly selectable in the library/CLI and persistent API/UI.
Saved profiles/reports retain their exact version and explanations use sealed
knowledge 0.3; old profiles/sources are unchanged.
See [full signatures and limits](expanded-comparisons.md#peer-templates).

## Measured parser coverage

Explicit `peer-baseline-0.3.0` uses actual
[adapter source-line coverage](parser-coverage.md), not the historical
`1 - parser_confidence` proxy. It is available through the library and local CLI.
The persistent API/UI currently select 0.1/0.2 only; selecting measured comparison
there, saving its report and binding explanation sources are still integration
work. Existing profiles, findings, canonical schemas and defaults are unchanged.

`build_measured_peer_baseline` consumes 3–20 `ParsedConfiguration` inputs. Each
contains the canonical configuration and its explicit `ParserCoverage`, from
`parse_configuration_with_coverage`. The existing five-field group, complete
parsing, distinct declared hostnames/hashes, target exclusion and non-future
collection-date gates apply unchanged. Missing, corrupt, differently bound or
zero-denominator reports are refused, not reconstructed from parser confidence.
The selected peers must be completely parsed, so their measured fractions are
zero by eligibility, **not** a learned distribution of real unsupported syntax.

The profile contains the unchanged 19-feature 0.2 property component with its
old confidence-proxy limit pinned to 1 (inert), plus the full source-ordered
coverage reports. Property values, templates, consensus threshold (default .75),
support counts and omissions retain their original meaning. The separate
`unparsed_fraction_limit` is the peer median zero plus an explicit tolerance
(default .05, range 0–1). Values strictly above the limit produce
`baseline.parser.unparsed_fraction_high`; equality does not. Source lines, not
universal vendor commands, are the unit. Hierarchical and set formats can have
different denominators; this does not establish equivalent-command recall.

`evaluate_measured_peer_baseline` returns `peer-comparison-report-0.3.0`, including
the exact target coverage, threshold, baseline fingerprint, retained/compared/
skipped features and findings. A partial target skips **every** property feature,
even below the tolerance and even when its finding list is empty. Parser warnings
can also make the result partial without increasing the measured numerator.
No absence is inferred from incomplete parsing.

Each finding binds its source, device, profile, full target-coverage SHA-256 and
new detector version in its deterministic UUID. Fraction evidence uses the final
unparsed source anchors/hashes, without raw commands or credential values.
Observed numerator/denominator/unit/adapter version are explicit. Confidence 1
describes exact source accounting, not fault probability. MEDIUM is review
priority; `(fraction - limit) / max(1 - limit, .01)`, capped at 1, is an
uncalibrated deviation score, not network risk. Property findings retain their
consensus-based confidence/score. A shared group or peer agreement is not an
approved security baseline, compliance result or independent device identity.

```powershell
.venv\Scripts\python.exe -m app.detection.baseline.peer_compare_cli --peer peer-1.cfg --peer peer-2.cfg --peer peer-3.cfg --current candidate.cfg --device-id f6156954-3f3b-4aa2-b693-5a710fe35d44 --device-role edge-router --site-class lab --service-profile transit --collected-at 2026-10-10T00:00:00+00:00 --comparison-version 0.3.0 --unparsed-fraction-tolerance 0.05
```

The CLI default remains 0.2.0. `--unsupported-ratio-tolerance` belongs only to
that historical version; `--unparsed-fraction-tolerance` only to 0.3.0. A flag
for the wrong version, nonfinite threshold or invalid input is refused rather
than ignored. Exit 0 means completed/no differences, 1 completed/differences,
2 refused, and 3 partial with JSON output. Inputs are explicit bounded UTF-8
regular files; no directory discovery, implicit source retention or input writes
occur. The full profile and evaluation each have an 8 MiB serialized limit,
so the combined per-peer arrays can be refused even if each file meets its
individual 2 MiB/10,000-line limit. Output contains hashes and may include
sensitive normalized values: keep it private.

Neither this detector nor the CLI runs policy, ML, a language model, formal
verification, vendor syntax validation or a device change. Accepted source lines
do not prove full semantics or safety. Authored IOS and both JunOS-form tests
exercise raw-text comparisons, counts, thresholds, provenance, partial skips,
contract refusals and historical CLI behavior; they are not an independent
real-corpus evaluation or an operational false-positive measurement.

[The measured local report](evaluation/owned-measured-peer-local.json) records
2113 full backend passes/23 skips/5 warnings, 82 related checks, focused Pydantic
2.14 compatibility and 28 actual installed CLI processes with per-child import
verification. The interface regression suite passed but measured comparison is
not yet wired to saved analysis or its UI. Historical coverage CI outcomes are
recorded separately; they do not verify this new detector's external environments.
