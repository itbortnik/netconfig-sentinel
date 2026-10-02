# Architecture

The first iteration is a modular monolith. `app.domain` owns stable contracts;
`app.parsers` owns content detection and vendor adapters; `app.api` exposes
process probes and an authenticated persistent deterministic-analysis workflow.
Ingestion, detection, verification, and explanation code
must depend on the domain contracts rather than on vendor parser internals.

The current persistent HTTP path is deliberately narrower than the offline tooling:

```text
Bearer token + bounded JSON upload + explicit device UUID
  -> text validation -> vendor parser -> encrypted canonical snapshot + audit
  -> policies + explicitly selected reference/peer comparison -> local explanations
  -> policy/peer risk (reference differences excluded)
  -> encrypted analysis + audit -> authenticated history/results
```

`app.db` owns short SQLAlchemy sessions and explicit Alembic migrations.
Snapshots and analyses are append-only through the exposed API. Writes and
their audit events commit together. Partial parsing keeps available findings
but suppresses the aggregate risk; exact reference comparison requires complete parsing.
Peer consensus is opt-in and persists the exact profile plus selected input fingerprints
inside the encrypted analysis, without a separate profile registry.
ML and formal verification remain unavailable in this HTTP path.
See [comparisons](api-comparisons.md), [API](persistent-api.md) and
[trust boundary](threat-model.md).

The browser is a React/TypeScript client of that same API, not a parallel detector.
It sends bearer credentials only to relative same-origin endpoints and validates
versioned responses before rendering. UI code never computes replacement detector
scores or verification statuses. Production assets are served under `/ui/` by
the same FastAPI process; Vite is only a loopback development proxy.
See [UI workflow and limits](web-interface.md).

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
seed, sample count, and score range. Explicit API training exports bounded numeric
trees into an encrypted immutable model registry with a training-snapshot manifest.
Inference loads validated JSON, never pickle or executable artifact classes, and
does not refit. API results bind the selected model ID, artifact hash and scores;
this experimental control model is not promoted or production-calibrated.

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
  -> reversible synthetic mutations + synthetic-only labels
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

Synthetic mutation is a separate post-sanitization path. A versioned recipe
selects an applicable existing construct, performs an exact line edit, records
the precondition and expected semantic effect, and validates the complete
result with the canonical vendor parser. Linked samples contain at most five
unique mutation types. Their labels always remain synthetic and cannot be
counted as confirmed real anomalies.

Transformer input preparation segments sanitized records into lossless source
blocks, trains a byte-level BPE vocabulary only on train representatives, and
encodes blocks into bounded windows with source-line alignment. The vocabulary
bundle records its dependency version, training fingerprint, policy and hash.
Validation/test records are encoded with the fixed trained vocabulary.

The first Transformer training boundary consumes train and validation windows
for masked-token reconstruction. Training masks vary by epoch; validation masks
remain fixed. A compact CPU encoder is optimized on train and its best epoch
is selected by validation loss. Test remains untouched. Model checkpoints bind
weights, tokenizer, and training report through a checksum manifest.

A supervised linear probe consumes token-mean embeddings from a frozen copy
of that encoder. Single-mutation examples are generated only after splitting;
their parent partition is preserved. The probe predicts mutation types or an
unmodified reference, not guaranteed healthy status. Validation selects the
head epoch; test remains unevaluated. It does not feed production risk fusion.

A separate frozen-encoder line head pools source-aligned token vectors per
current-file line. Synthetic insert/replace targets supervise a weighted binary
objective. Deletion-only variants have no current-line target and are excluded,
not mapped to innocent neighboring lines. Inference needs only the current
configuration; scores remain uncalibrated and outside production risk fusion.
