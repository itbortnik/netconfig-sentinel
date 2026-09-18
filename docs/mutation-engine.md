# Synthetic mutation engine

Engine version `config-mutation-0.1.0` creates reproducible anomaly examples
only from already sanitized `ImportedDatasetRecord` values. It never changes
the source model in place and never marks a generated example as a confirmed
real anomaly.

## Mutation contract

Every `SyntheticMutationSample` contains:

- a content-derived mutation ID, source-record reference, engine version, and
  deterministic seed;
- original and mutated SHA-256 values plus only the mutated sanitized text;
- one unique synthetic label per requested mutation type;
- the precondition, exact original and replacement lines, expected effect, and
  inverse data for every operation;
- final changed line numbers calculated from the complete diff;
- canonical-parser validation and a separate external-validation status;
- explicit limitations.

`reverse_mutation` checks the mutated hash and every replacement context before
applying operations in reverse order. It succeeds only when the reconstructed
text matches the original SHA-256. The original configuration body is not
copied into the sample.

One sample may contain up to five distinct linked mutations. If any requested
precondition is absent, parsing fails, a new warning or unsupported fragment is
introduced, or an expected canonical effect is not observed, generation fails
without returning a partially trusted sample.

## Supported classes

The registry contains all minimum classes required for the dataset pipeline:

1. AAA disabled;
2. Telnet enabled;
3. SNMP downgrade;
4. permissive ACL;
5. missing ACL entry;
6. VLAN mismatch;
7. incorrect access/trunk mode;
8. BGP remote AS mismatch;
9. missing BGP neighbor;
10. OSPF area mismatch;
11. removed static route;
12. management exposure;
13. missing NTP/Syslog destinations;
14. route-map order change;
15. conflicting interface IP address.

Cisco IOS flat syntax supports all 15. JunOS `set` syntax supports every class
except the Cisco-specific route-map order change. JunOS hierarchical syntax is
deliberately rejected by this engine version: the normal parser supports it,
but safe structural editing needs a brace-aware editor rather than line
substitution.

## Validation boundary

Before mutation, the engine checks the sanitizer version, sanitized-text hash,
explicit vendor hint, parser detection, and supported syntax style. After mutation it parses
the entire result again, rejects new parser warnings or unsupported fragments,
and confirms the expected change in the canonical model.

The route-map recipe is marked `partial` because route-map semantics are not
yet covered by the canonical parser. Its exact line edit and reversal are
checked, and the surrounding configuration is parsed, but this is not claimed
as semantic route-map validation. All other accepted recipes are marked
`passed` at the canonical-parser boundary.

External network-behavior validation is `not_run` until that adapter exists.
Parser validation is not proof that a real device will accept the candidate or
that the mutation has the intended topology-wide impact.

## Avoiding generator artifacts

The engine preserves line endings, indentation, neighboring text, and the
source vendor's notation. A stable seed selects among applicable candidates
and, where valid, equivalent command spellings. It does not append every
anomaly to one fixed location or reformat the whole file. Dataset construction
should vary seeds and source templates, then evaluate real confirmed anomalies
separately from synthetic examples.

## Usage

```python
from ml.mutation import MutationType, mutate_configuration, reverse_mutation

sample = mutate_configuration(
    sanitized_record,
    (
        MutationType.BGP_REMOTE_AS_MISMATCH,
        MutationType.MISSING_NTP_SYSLOG,
    ),
    seed=17,
)

original_text = reverse_mutation(sample, sample.mutated_text)
```

`list_applicable_mutations` can be used to inspect a record before selecting a
balanced mutation plan. Applicability is computed by generating and validating
each class independently, not by matching a declared vendor alone.
