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

The parser-confidence deficit (`1 - parser_confidence`) is compared with the
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
version is currently local-library/CLI only; saved API/knowledge integration is
separate. See [full signatures and limits](expanded-comparisons.md#peer-templates).
