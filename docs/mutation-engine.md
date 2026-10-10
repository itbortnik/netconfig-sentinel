# Synthetic mutation engine

The default engine version `config-mutation-0.1.0` creates reproducible anomaly examples
only from already sanitized `ImportedDatasetRecord` values. It never changes
the source model in place and never marks a generated example as a confirmed
real anomaly. The explicit opt-in `config-mutation-0.2.0` extends the offline
generator to a bounded multiline hierarchical JunOS slice. It does not replace
the default, reserialize historical samples, train a model or apply device patches.

## Mutation contract

Every `SyntheticMutationSample` contains:

- a content-derived mutation ID, source-record reference, engine version, and
  deterministic seed;
- original and mutated SHA-256 values plus only the mutated sanitized text;
- one unique synthetic label per requested mutation type;
- the precondition, exact original and replacement lines, expected effect, and
  inverse data for every operation;
- final textual localization, with version-specific deletion handling below;
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
deliberately rejected by the default 0.1 engine. The explicit 0.2 engine supports
the same 14 JunOS-applicable classes with a brace-aware editor; it accepts neither
IOS nor JunOS `set` inputs. The route-map mutation is not applicable to it.

## Hierarchical JunOS 0.2 boundary

Input must already be sanitized, have a valid source hash and explicit Juniper
vendor hint, and parse without warnings. The editor accepts multiline blocks
with one statement or block delimiter per physical line. It preserves LF/CRLF,
the trailing-newline choice, tabs, quoted punctuation and supported comments.
It rewrites selected spans rather than pretty-printing the configuration.

The structural preflight refuses mixed `set`/hierarchical input, unbalanced
braces, missing terminators, single-line nested blocks, inline block comments,
duplicate scalar/keyed statements, equivalent duplicate OSPF area IDs, groups,
inheritance and inactive/replace/delete directives. Before canonical parsing it
limits input to 1 MiB, 50,000 lines, 4,096 nodes and 64 nesting levels. Candidate
planning also refuses more than 64 interface addresses. These are defensive
offline bounds, not a vendor grammar or performance SLA.

Recipes use canonical provenance and full hierarchy identity. In particular,
ACL terms are qualified by family/filter/term; BGP AS changes affect one exact
neighbor using a native neighbor block and preserve group inheritance; OSPF
changes move one complete interface subtree, including its metric, to a
different normalized area. AAA and NTP/Syslog removals must not swallow unknown
children. IPv6 address/ACL/neighbor mutations preserve the address family.

Unrelated unknown fragments may remain only when their raw-text multiset is
unchanged. Such a result is explicitly `partial`, not completely validated.
Edits that would consume an unsupported target subtree are refused. Every
operation and the final linked result are reparsed and checked for their
expected canonical effects. Generation also performs exact hash-checked
reversal before returning a 0.2 sample. Separate authored refusal tests cover
unsupported input and absent preconditions; they are not real-corpus accuracy.

## Final line localization and deletion labels

Historical 0.1 samples keep their nonempty `affected_lines` and serialization
unchanged, including the old nearest-result-line anchor for deletions. Do not
reinterpret this historical anchor as causal line-level ground truth.

New 0.2 samples require `mutation-localization-0.1.0`: original/result line
counts and ordered, bounded `insert`/`delete`/`replace` textual diff hunks over
the **original parent and final result**, not intermediate operation offsets.
Each hunk records one-based start positions and separate source/result counts.
Sample-level `affected_lines` contains only actual changed result lines. A
pure deletion therefore has empty `affected_lines` and explicit removed source
spans with `mutated_line_count=0`; its result start is an insertion position,
not an invented surviving anomalous line. Reversal recomputes and verifies the
complete localization against the reconstructed parent.

Operation-level spans and `affected_lines` retain the historical intermediate
edit/reversal contract and deletion anchors. They must not be used as final
training coordinates. Final textual differences are not semantic causal truth:
a deletion-only anomaly needs missing-setting/source-span supervision or a
masked/absent line target, not an all-negative healthy line example. This release
does not automatically convert these samples into a training corpus or alter
historical training/evaluation artifacts. Linked labels and LF/CRLF views also
do not constitute independent parent configurations or networks.

## Validation boundary

Before mutation, the engine checks the sanitizer version, sanitized-text hash,
explicit vendor hint, parser detection, and supported syntax style. After mutation it parses
the entire result again, rejects new parser warnings or unsupported fragments,
and confirms the expected change in the canonical model.

The route-map recipe is marked `partial` because route-map semantics are not
yet covered by the canonical parser. Its exact line edit and reversal are
checked, and the surrounding configuration is parsed, but this is not claimed
as semantic route-map validation. Other accepted 0.1 recipes are marked `passed`
at the canonical-parser boundary; 0.2 results with preserved unknown fragments
remain `partial` as described above.

External network-behavior validation of these generated samples is `not_run`;
the separate change-review/Batfish workflow is not automatically invoked here.
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

For the hierarchical slice both functions require an explicit version:

```python
from ml.mutation import STRUCTURAL_MUTATION_ENGINE_VERSION, list_applicable_mutations

applicable = list_applicable_mutations(
    sanitized_hierarchical_record,
    seed=17,
    engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION,
)
sample = mutate_configuration(
    sanitized_hierarchical_record,
    (MutationType.BGP_REMOTE_AS_MISMATCH, MutationType.MISSING_NTP_SYSLOG),
    seed=17,
    engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION,
)
assert reverse_mutation(sample, sample.mutated_text) == sanitized_hierarchical_record.sanitized_text
```

The [owned diagnostic report](evaluation/owned-hierarchical-junos-mutations.json)
separates authored functional/reversal checks, actual installed-package execution,
legacy serialization compatibility and unrun external checks. It measures no
independent detector quality, real confirmed labels or device acceptance.
