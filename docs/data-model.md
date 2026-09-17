# Data model

`CanonicalConfig` is the sole return type of every `VendorParser`. Public models
forbid unknown fields and validate confidence ranges, positive ordered line
numbers, filename safety, and SHA-256 representation.

Provenance is stored per normalized field through `SourceLocation`. The location
contains one-based source lines, a SHA-256 of the exact contributing text, and
the parser confidence for that fact.

`Finding` separates three concepts which must not be conflated:

- `severity`: potential impact;
- `confidence`: detector certainty;
- `anomaly_score`: statistical deviation.
