# Expanded local reference and peer comparison

The opt-in `expected-config-0.2.0` and `peer-baseline-0.2.0` detectors extend
supported canonical-IR comparisons. They do not silently broaden the released
0.1.0 detectors, existing API analyses, saved explanations or model artifacts.
The library and local CLI workflows are also available through explicit API/UI
selection, encrypted versioned persistence and sealed explanation sources.

## Same-device reference

`create_expanded_reference` captures the caller-selected source, device identity,
45 field families, current provenance and a bounded JSON contract.
`compare_expanded_reference` requires the same device UUID, vendor, platform and
hostname. Both inputs must have complete parsing: no warnings or unknown
fragments and `parser_confidence == 1`. This is not vendor syntax qualification.

| Area | Supported normalized values |
| --- | --- |
| Management | SSH enablement/version, Telnet, AAA, SNMP versions, actual NTP and Syslog server sets |
| Local users | Presence, privilege, login class, UID, authentication kind/encoding; no password, hash or key values |
| Interfaces | Presence, enabled state, mode, access/native/allowed VLAN selections and address sets |
| VLANs | Identifier/name inventory |
| ACLs | Presence, family/kind and ordered rules, including protocol, addresses, port expressions, options and sequence/term labels |
| Prefix lists | Presence, family and ordered entries with action, prefix, ge/le and sequence |
| BGP | Process presence, local AS/router ID; neighbor presence, family, remote AS, group, session type, update source and enabled state |
| OSPFv2 | Presence, process/version/router ID/passive default; network areas and interface presence/area/passive/cost |
| Static routes | Destination-keyed next hop, outgoing interface, preference and discard target sets |

Only explicit supported IR values are compared. A present object's null
property is different from an absent object, but null is not interpreted as an
effective vendor default. Names and addresses are retained for this same-device
comparison. Description and source formatting are outside the value signature.
Set-like inventories are canonicalized; ACL/prefix-list entry order, port
expressions and option order are retained as represented by the IR. This does
not interpret vendor sequencing, effective ACL attachment or policy intent.

Each finding binds the current source hash, selected reference ID/source hash
and the exact reference-facts fingerprint. Reference locations remain separate
from current evidence. Removed facts have no invented current line. Fingerprints
and deterministic UUIDs identify this exact run; they are not publisher
signatures or proof that the reference was approved. MEDIUM is a review priority;
confidence/anomaly score 1 describes an exact difference, not a fault probability.

```powershell
.venv\Scripts\python.exe -m app.detection.baseline.compare_cli --reference previous.cfg --current candidate.cfg --device-id f6156954-3f3b-4aa2-b693-5a710fe35d44 --reference-id selected-snapshot --comparison-version 0.2.0
```

The default remains `0.1.0`, including its existing report shape. Explicit 0.2.0
returns `expected-comparison-report-0.2.0`, its detector version and reference
fingerprint. Exit 0 means no supported differences, 1 means differences, and
2 means refused input/arguments. No exit code establishes network safety.

## Peer templates

`build_expanded_peer_baseline` requires 3–20 completely parsed configurations
and the full `vendor + platform + device_role + site_class + service_profile`
group. Declared hostnames (case-insensitive) and source hashes must be distinct.
The target cannot share either identity with the selected population or precede
a declared peer collection date. These are anti-copy/time-binding checks, not
independent device identity, network ownership or historical-time attestations.

The 19 eligible exact-consensus features are management's seven value fields,
local-user templates, interface templates, VLAN inventory, ACL templates,
prefix-list templates, BGP presence/local AS/router-ID presence/neighbor
templates, OSPF presence/process templates and complete static-route targets.
Default support is 75%; no feature below threshold is guessed. The saved profile
explicitly partitions all eligible features into retained and omitted fields
and pins every selected hostname/source/date, support count and threshold.

Peer templates differ deliberately from same-device facts:

- Router-ID **presence**, not individual router-ID values, is compared.
- Interface names/units and individual IP values are omitted; enabled/mode/VLAN
  settings and distinct-address family/prefix-length multiplicity are retained.
- BGP neighbor addresses/group labels are omitted; family, remote AS, session
  type, enabled state and update-source shape are retained. IP update sources
  compare presence/family, while named update interfaces compare their names.
- OSPF process IDs, interface names and network addresses are omitted. Version,
  router-ID presence, passive default, network prefix-length/area and interface
  area/passive/cost patterns are retained with multiplicity.
- ACL/prefix-list names and sequence/term labels are omitted; ordered supported
  predicates/actions/ports/options are retained. Local-user names/UIDs are
  omitted; privilege/class and authentication metadata are retained.
- VLAN identifier/name values, NTP/Syslog servers and static-route addressing,
  next hops, interfaces, preference/discard values remain exact design values.

This is a bounded triage profile, not a topology-aware learned security policy.
The selected population may be biased or uniformly wrong. Individual design
differences can be valid, and a field without agreement is not proven safe.
Support determines confidence/deviation indicators, not calibrated fault risk.

`evaluate_expanded_peer_baseline` returns an `ExpandedPeerEvaluation`, not a
bare list. It records source/profile fingerprints, compared/skipped features,
findings and completed/partial status. A partial target skips **all** property
comparisons: unsupported syntax cannot become evidence of a missing setting.
Only the parser-confidence deficit (`1 - parser_confidence`) is checked against
the explicit tolerance (default .05; peer median is zero because peers must be
completely parsed). This deficit is a proxy, not a census of vendor commands.
An empty partial finding list is still partial, never a successful comparison.

New uploads now have a separate [measured source-line coverage report](parser-coverage.md).
It is not substituted into these released detector contracts: their saved
fingerprints and historical findings retain the original deficit semantics.
An explicit [peer 0.3 library/CLI/API/UI selection](baseline.md#measured-parser-coverage)
compares the measured fraction while reusing these property templates. Its saved
profile/report and sealed explanation sources have separate versions; 0.2 and
historical snapshots remain unchanged. A 0.3 reference-only request still uses
the released 0.2 reference detector, not a new reference grammar.

```powershell
.venv\Scripts\python.exe -m app.detection.baseline.peer_compare_cli --peer peer-1.cfg --peer peer-2.cfg --peer peer-3.cfg --current candidate.cfg --device-id f6156954-3f3b-4aa2-b693-5a710fe35d44 --device-role edge-router --site-class lab --service-profile transit
```

The CLI takes only explicitly named files and inventory labels; it does not
discover a directory or infer trusted inventory. The default version remains 0.2;
explicit 0.3 uses its separate measured-fraction tolerance flag. The report
includes the exact profile and evaluation. Exit 0 is a completed comparison without differences,
1 completed with differences, 2 refused, and 3 partial (with a JSON report).
Optional `--collected-at` supplies one declared timezone-aware batch date for
reproducibility. Without it, the current run time is used, not file modification
time or verified equipment history. Threshold/tolerance overrides must be finite.

## Boundaries and verification

Both commands only read explicitly selected regular UTF-8 `.cfg/.conf/.txt`
files (BOM allowed), up to 2 MiB/10,000 lines per file, using the existing
link/path/control-character gates. They do not write input files, persist a
database, contact devices or external providers, or run policy, ML or Batfish.
Errors do not echo configuration values or source paths. Report values can
contain sensitive addressing/account metadata: keep stdout private.

Contracts reject extra fields, invalid primitive types/enumerations/ranges,
duplicate or incomplete fact/profile inventories and wrong detector versions.
Each fact value is bounded to 512 KiB serialized JSON, each reference/profile
projection to 8 MiB, and a reference to 50,000 facts. Ambiguous duplicate object
identities are refused. These bounds do not authenticate caller-supplied facts.

Owned tests cover two-vendor raw-text-to-finding paths with actual hashes/line
anchors, value changes, removals/nulls, ordering, secrets excluded from facts,
peer consensus/omissions/source order, self/duplicate/future/group gates,
partial targets, invalid contracts and both local entry points. IR-only mutation
tests are contract checks, not additional independent raw-source examples.
No real confirmed labels, detection-quality metric, ML inference, data-plane
result, device syntax/access/rollback qualification or engineer approval is
claimed. Existing encrypted API analyses and immutable knowledge releases keep
their original comparison versions; new opt-in results do not rewrite history.

[The measured local report](evaluation/owned-expanded-local-comparisons.json)
records 1903 full-suite passes/23 skips/5 warnings, 128 focused checks, focused
Pydantic 2.14 compatibility and 12 actual CLI processes from an installed wheel.
These are functional checks, not independent detection-quality measurements.

## Persistent API and interface

Select `comparison_version: "0.2.0"` together with a saved reference and/or
3–20 saved peers in the [analysis request](api-comparisons.md). The interface's
“Область сравнения” selector sends this choice explicitly. Its default remains
0.1.0 and resets on logout/reload. An unselected version does not upgrade an old
run. With no comparison inputs, selecting 0.2.0 still gives policy-only behavior.

New results use `analysis-api-0.4.0` and `comparison-context-0.2.0`, including
when an experimental forest is explicitly selected. The encrypted context stores
exact snapshot IDs/hashes/times, the expanded peer profile and its evaluation.
Profile fingerprint, source/device, inventory, support counts, report status and
findings are cross-checked. Old 0.1/0.2/0.3 analyses retain their original shape.
No schema migration, automatic profile refresh or baseline approval is implied.

The saved report distinguishes retained features actually compared, properties
skipped for incomplete parsing, and features omitted for lack of consensus.
A partial report can have no findings; it still skips all selected properties
and cannot produce a risk score. The parser ratio is a confidence-deficit proxy,
not an exact unknown-command census. The interface displays these separately.

Deterministic explanations recompute the exact selected detector before saving.
Explicit source retrieval binds new findings to `project-knowledge-0.3.0`, sealed
from published commit `20efc00827f1b0e0bbbd27ac55fd3a75f5167fc1`. Original detector
versions keep their old releases. These are internal project documents, not
vendor manuals, engineer approvals or proof of factual/semantic quality.
Optional semantic retrieval requires a separate external 0.3 index pin; absence
returns 503 rather than silently using an old index. Neither comparison nor
explicit retrieval calls a language model, Batfish or a device.

[The API/UI/installed report](evaluation/owned-expanded-api-comparisons.json)
records 1952 full-suite passes/23 skips/5 warnings, 370 frontend unit tests,
116 regular and 22 synthetic-model browser cases, 14 installed analysis/restart
round trips and four actual isolated CPU document-worker requests. The new
43-row index reaches the expected section for five of six reused authored queries
at both rank one and rank four. These checks do not qualify independent quality,
instruct generation, a real network or production deployment.
