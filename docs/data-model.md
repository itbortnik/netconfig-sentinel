# Data model

`CanonicalConfig` is the sole return type of every `VendorParser`. Public models
forbid unknown fields and validate confidence ranges, positive ordered line
numbers, filename safety, and SHA-256 representation.

Provenance is stored per normalized field through `SourceLocation`. The location
contains one-based source lines, a SHA-256 of the exact contributing text, and
the parser confidence for that fact.

Network policy is represented by typed `AclConfig`/`AclRule` and
`PrefixListConfig`/`PrefixListRule` objects. IP networks are canonicalized,
address families and prefix-length bounds are validated, and every normalized
rule retains source provenance. JunOS prefix-list membership intentionally has
no permit/deny action because the action belongs to the policy that consumes
the list.

`StaticRouteConfig` stores one IPv4 or IPv6 destination and one forwarding
target: next-hop address, outgoing interface, or discard action. It validates
address-family consistency, canonicalizes networks and addresses, and keeps
the configured preference or administrative distance without inventing vendor
defaults.

`BgpConfig` contains one global local AS, optional IPv4 router ID, and typed
`BgpNeighborConfig` entries. Neighbor addresses are canonicalized, AS numbers
use the 32-bit ASPLAIN range, and the model keeps the session family/type,
group, update source, description, administrative state, and per-field
provenance. JunOS group values are resolved into each neighbor explicitly.

`OspfProcessConfig` models OSPFv2 router identity, passive-default state,
network-to-area statements, and interface-to-area membership. Decimal and
dotted area IDs normalize to the same dotted 32-bit value; interface cost and
passive overrides retain their own provenance.

`Finding` separates three concepts which must not be conflated:

- `severity`: potential impact;
- `confidence`: detector certainty;
- `anomaly_score`: statistical deviation.
