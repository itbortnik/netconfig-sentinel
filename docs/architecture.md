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
