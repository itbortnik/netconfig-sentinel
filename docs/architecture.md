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
