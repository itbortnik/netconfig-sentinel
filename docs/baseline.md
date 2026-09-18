# Peer-group baseline

The peer baseline detects normalized configuration values that differ from a
well-defined group of comparable devices. It is deterministic and does not
replace policy checks: a common configuration can still violate policy, while
a secure but unusual configuration can still require review.

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
- The profile is an in-memory contract in this iteration; persistence and
  time-aware version selection belong to the API/database stage.
- Peer agreement is not evidence of compliance and cannot reduce the severity
  of a deterministic policy finding.
