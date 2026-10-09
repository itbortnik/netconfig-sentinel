# Measured adapter source-line coverage

New configuration uploads include a separate `parser_coverage` report. The same
report is returned by authenticated snapshot GET, stored in the existing encrypted
snapshot payload, and displayed in the interface. No database migration or model
activation is needed. The library entry point is
`app.parsers.coverage.parse_configuration_with_coverage`: it validates the existing
2 MiB UTF-8/10,000-line budgets, parses once, and returns the unchanged canonical
configuration plus coverage. This is preparation for comparing the actual unknown
fraction, not a replacement for the released peer detectors.

## Unit and denominator

`parser-coverage-0.1.0` counts **adapter source lines**: precisely the items of
Python `str.splitlines()` used by the current Cisco and JunOS adapters. Headers,
leaves and repeated settings count separately. It does not tokenize multiple
statements on one line, expand inheritance or convert a hierarchical block into
equivalent flat-set commands. Equivalent configurations in different formats can
therefore have different denominators. The adapter version is pinned separately
(`cisco-ios-source-lines-0.1.0` or `junos-source-lines-0.1.0`); future changes in
accounting must not reinterpret saved reports.

Every input line has exactly one ordered, one-based unit:

- `unparsed`: belongs to the **final** canonical unparsed fragment anchors,
  including late builder refusals. This wins over every other classification.
  Several fragments referencing one line count once; repeated source lines remain
  different units.
- `ignored`: blank lines or comments ignored by the existing adapter. IOS uses
  stripped blank/`!` lines. JunOS follows the existing `_strip_comment` behavior:
  leading `#`, `/*`, `*`, or the part before `//`; no new quote-aware or multiline
  comment grammar is claimed.
- `structural`: accepted exact IOS `end`, `exit`, `configure terminal`,
  `exit-address-family`, or accepted JunOS closing `}`/`};` after comment stripping.
  If the adapter refused one in its actual context, it remains `unparsed`.
- `accepted`: every remaining source unit accepted by the current adapter,
  including supported block/context headers and repeated settings. Acceptance does
  **not** establish complete semantic normalization or authoritative vendor syntax.

`command_units = accepted_units + unparsed_units` and
`unparsed_fraction = unparsed_units / command_units`. Structural and ignored lines
are excluded. A zero denominator produces **null**, not zero. A missing hostname
warning is not an additional unknown command. The fraction is not
`1 - parser_confidence`, detector confidence, anomaly score or network risk.
Canonical parser confidence and its historical calculation are unchanged.

## Binding, history and privacy

The strict, bounded report binds the exact UTF-8 input SHA-256 (including original
line endings), vendor/platform, counts and each line's SHA-256 (without its line
terminator). It contains no raw commands, credential values or inventory labels.
Snapshot validation cross-checks source/vendor/platform and final unparsed
anchors/text hashes. Counts, order, denominator and fraction must agree. This is
an integrity/accounting check, not authentication of operator-supplied data or a
proof of each accepted command's semantics. Hashes are linkable and may also be
confidential; use the same access and encrypted-storage boundaries as snapshots.

Coverage does not retain the original source implicitly. Optional original-text
retention still requires its separate upload consent. Partial parsing continues
to suppress final risk, even when the measured fraction is small or zero.
`proves_vendor_syntax` is always the literal false.

Legacy snapshots without a report remain readable and serialize without a new
field. History is not reparsed or silently upgraded. The interface shows
“Покрытие не измерено”, not an inferred ratio. History-list summaries do not carry
the per-line array. Canonical schemas 1.0/1.1, parser golden bytes, forest features,
existing reference/peer fingerprints and saved analysis/explanation bindings are
unchanged. Peer-baseline 0.1/0.2 still use their documented confidence-deficit
proxy; integrating measured coverage needs a new explicit comparison contract.

## Checks and limits

`backend/tests/unit/test_parser_coverage.py` exercises both JunOS forms and IOS,
comments/delimiters/context, repeats, late unsupported BGP lines, budgets, strict
metadata and unchanged canonical golden inputs. API tests exercise encryption,
GET/restart, partial risk, absent original retention, old-history shape and corrupt
source/anchor/hash rejection. The PostgreSQL history test also checks the uploaded
report; actual PostgreSQL execution requires its explicit test environment.
Frontend checks exercise strict accounting/source/anchor binding, missing and
zero-denominator presentation, and desktop/mobile browser uploads. The historical
browser case uses a synthetic old wire shape; it is not a new legacy deployment.
These are authored functional checks, not parser-recall measurements on an
independent real corpus, a vendor syntax check, model evaluation or formal safety.

[The measured functional report](evaluation/owned-parser-coverage.json) records
2044 full backend passes, 23 explicit skips and five warnings; 416 frontend unit
checks; 134 regular and 22 synthetic-model browser cases. An installed wheel
verified four upload/analysis/restart paths, one unchanged legacy snapshot and
four unchanged canonical golden pairs. No ML or engine was called by that
installed coverage diagnostic. Peer comparison of this fraction remains open.
