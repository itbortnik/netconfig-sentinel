# Architecture

The first iteration is a modular monolith. `app.domain` owns stable contracts;
`app.parsers` owns content detection and vendor adapters; `app.api` only exposes
process probes. Future ingestion, detection, verification, and explanation code
must depend on the domain contracts rather than on vendor parser internals.

Parser selection is explicit and deterministic:

```text
raw text -> vendor evidence -> parser registry -> CanonicalConfig
```

No parser may silently drop a non-empty unsupported command. Unknown fragments
carry their original text, one-based line numbers, a hash, and zero parsing
confidence. The aggregate confidence is reduced according to the unsupported
line ratio.

Peer comparison is a separate deterministic detector:

```text
explicit peer inventory -> consensus profile -> target comparison -> Finding[]
```

The profile depends only on canonical contracts and never on vendor parser
internals. Group membership requires vendor, platform, device role, site class,
and service profile. Policy findings and baseline findings remain independent
so common misconfiguration cannot be treated as compliant.

The statistical control path reuses the same group identity:

```text
CanonicalConfig -> versioned numeric features -> Isolation Forest -> Finding[]
```

Training metadata keeps the feature schema, library version, deterministic
seed, sample count, and score range. The fitted estimator remains in memory in
this iteration; persistence will use the later model registry boundary.

Completed detector results converge through a transparent fusion boundary:

```text
policy + peer + statistical + future transformer + verification -> RiskAssessment
```

Unavailable signals are explicit and their weights are redistributed. Critical
policy violations and verified loss of reachability have minimum-score
guardrails that the weighted formula cannot reduce.

Dataset preparation has a separate trust boundary before parsing or training:

```text
reviewed source manifest + local files
  -> bounded validation
  -> in-memory sanitization
  -> pseudonymous ImportedDatasetRecord[]
  -> exact and normalized hashes
  -> MinHash/LSH candidates + exact similarity verification
  -> representatives + duplicate evidence + template groups
  -> entity closure + chronological allocation
  -> isolated train / validation / test partitions
  -> quality, provenance, privacy, balance, and scale report
  -> non-overwriting sanitized artifact directory
```

Only sources with an approved license or authorization and the requested use
may cross this boundary. Raw configuration text and source paths are never
members of the imported record. Stable aliases are scoped by source and
topology so relationships within one topology survive without linking two
unrelated sources.

Deduplication never accepts an LSH collision as evidence by itself. Candidate
pairs must pass exact Jaccard comparison over normalized command-line and
adjacent-line tokens. Template equality is reported separately and only helps
candidate discovery; it cannot remove a record on its own.

Dataset splitting computes connected atomic groups over source-scoped network,
site, and device identities plus duplicate-cluster links. Allocation never
breaks those groups. Groups are ordered by their latest capture time and
assigned to contiguous train, validation, and test regions; any remaining time
range overlap caused by a long-lived group is explicit in the split audit.

The quality boundary binds the exact sanitized inputs, deduplication policy,
split policy, and assignments into one pipeline fingerprint. Blocking source,
integrity, privacy, or leakage findings prevent persistence. Distribution and
time-range limitations remain warnings because they require review without
silently changing entity-isolated partitions. Scale targets are reported as
actual-versus-required values and never converted into dataset claims.

The artifact writer persists only sanitized representatives and audit data. It
creates a new directory, marks it incomplete while writing, uses exclusive file
creation, and refuses an existing target. A manifest binds every content file
to its byte count and SHA-256; loading checks the complete inventory and rejects
symbolic links, incomplete output, extra files, and changed content.
