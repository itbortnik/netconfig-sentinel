# Data model

`CanonicalConfig` is the sole return type of every `VendorParser`. Public models
forbid unknown fields and validate confidence ranges, positive ordered line
numbers, filename safety, and SHA-256 representation.

Provenance is stored per normalized field through `SourceLocation`. The location
contains one-based source lines, a SHA-256 of the exact contributing text, and
the parser confidence for that fact.

`DeviceInfo` carries optional inventory metadata (`role`, `site`, `site_class`,
and `service_profile`). Peer analysis requires role, site class, and service
profile explicitly; vendor parsers do not infer them from hostname conventions.

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

`PeerBaseline` stores a complete peer-group key, sample count, consensus
threshold, supported exact-value features, and the peer-derived unsupported
syntax limit. Each `ConsensusFeature` records its support count so detector
confidence and evidence remain auditable.

`StructuredFeatureVector` binds every numeric vector to a fixed ordered schema
and diagnostic provenance. `IsolationForestMetadata` records the peer group,
training parameters, dependency version, feature medians/scales, and training
score range separately from the in-memory estimator.

`RiskAssessment` separates the fused score and risk band from its
`RiskComponent` inputs. Every component records availability, raw score,
configured weight, normalized effective weight, and contributing finding IDs;
guardrails and missing-signal limitations remain explicit.

`DatasetManifest` binds every candidate file to a reviewed `DatasetSource`.
The source records origin, source class, license identifier, review status,
allowed uses, collection time, and authorization reference when real data is
used. `DatasetRecord` adds a safe relative path, grouping identifiers, capture
time, optional vendor and role hints, and an optional expected SHA-256.

`ImportedDatasetRecord` is the post-sanitization boundary. It contains only
pseudonymous grouping identifiers, sanitized text, integrity hashes, byte and
replacement counts, and the sanitization version. It intentionally has no raw
text, source path, origin URL, or reversible identity mapping.
