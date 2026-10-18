# Explicit Cisco route-map configured facts

The opt-in canonical profile `1.2` records a bounded IOS/IOS-XE route-map subset.
Default parsing remains `1.1`; reading a saved snapshot never upgrades its profile.
This closes part of the dataset generator's configured-order validation gap.
It does not evaluate routes or qualify a configuration for application.

## Entry points and supported values

Use `parse_configuration(text, filename="owned.cfg", schema_version="1.2")`, or
send `parser_schema_version: "1.2"` in a configuration upload. In the interface,
select **Разбирать секции Cisco route-map** after choosing the input. The choice
starts off and resets after changing the device, filename or content, selecting
a file, or successfully saving. Original-source retention remains a separate
explicit consent. JunOS is refused for this profile, including inputs with no
route-map statements. Unknown/coerced profile values are refused without echoing
submitted content.

Supported global headers are `route-map NAME permit|deny SEQUENCE`, with an explicit
unique integer sequence from 0 through 65535. Each clause may contain one
`match ip address prefix-list NAME ...` line with up to 64 distinct names and one
`set metric INTEGER` from 0 through 4294967295. Keywords and whitespace are
normalized; names retain case. Clauses are sorted by numeric sequence, with their
own actions, child values and original source-line/hash provenance. Empty clauses
have no invented match or metric value. This records configured text only.

The parser bounds input to 1 MiB UTF-8, 50,000 lines and 1,024 recognized clauses.
The upload/coverage path also retains its smaller 10,000-line limit. These are
defensive limits, not platform limits or a performance qualification.

Unsupported children stay in unparsed fragments; recognized siblings can survive
with `normalization_complete=false`. Repeated sequence numbers, including different
numeric spellings, are ambiguous. Repeated match/metric children are not merged
or resolved by guessing the last value. Unsupported or deletion headers prevent
a complete claim for their map. Comments do not terminate a clause. Opaque
banner/macro/script input disables route-map normalization conservatively.

The subset excludes implicit action/sequence, `continue`, `call`, ACL/IPv6 matches,
compound/relative metrics, reference resolution, route-map attachment, inheritance
and effective route selection. A complete normalized map means that its bounded
configured clauses were recognized; it does not mean that referenced prefix lists
exist, that any route matches, or that the policy is safe. Cisco documents both
numeric sequence ordering and application-dependent behavior in its
[route-map guide](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/49111-route-map-bestp.html).
The bounded numeric fields follow the
[IOS-XE route-map data model](https://netascode.cisco.com/docs/data_models/iosxe/device/route_map/).

## Snapshots, comparison and coverage

Profile 1.2 snapshots serialize `route_maps` and retain local device accounts.
Profiles 1.0/1.1 omit the new field, including when the in-memory default is empty.
Source retention reparses with the saved profile before accepting exact source
text. The UI displays configured clause order, source lines and partial warnings.
Read-only object diff compares ordered configured clauses; it does not simulate
their routing consequences.

Coverage uses `cisco-ios-route-maps-source-lines-0.1.0`, bound to profile 1.2 and the
same source hash. Relabeling a saved old/new report is refused even when counts
happen to match. Measured peer explanations accept the new Cisco adapter and
retain the existing source, platform and protocol bindings. No model is invoked
by parsing, comparison, or deterministic explanation preparation.

## Explicit mutation engine 0.3

```python
from ml.mutation import ROUTE_MAP_MUTATION_ENGINE_VERSION, MutationType
from ml.mutation import mutate_configuration, reverse_mutation

sample = mutate_configuration(
    sanitized_record,
    (MutationType.ROUTE_MAP_ORDER_CHANGE,),
    seed=17,
    engine_version=ROUTE_MAP_MUTATION_ENGINE_VERSION,
)
assert reverse_mutation(sample, sample.mutated_text) == sanitized_record.sanitized_text
```

The input must already be a sanitized observed-record contract; an authored
functional example does not establish genuine device metadata or healthy labels.
Engine `config-mutation-0.3.0` accepts Cisco and preserves the other 14 existing
recipes. It selects two distinct complete configured clause bodies in one map,
swaps their sequence headers, reparses both inputs with profile 1.2 and confirms
the same sequence set and body multiset with exactly two changed ordered positions.
Identical bodies and incomplete/ambiguous selected maps are refused. Candidate
selection is bounded to 4,096 pairs. Up to five linked edits retain final
source/result localization and exact text reversal.

`route-map-order-validation-0.1.0` binds the actual before/after clause facts and
provenance to both source hashes. Replay revalidates the artifact, reverses exact
edits, checks both intermediate operation coordinates and each recorded canonical
effect, and reproduces final localization, parser counts/status and clause facts.
Unrelated unknown fragments may remain only unchanged and keep status `partial`.
`passed` describes the canonical-parser boundary only. The hash bindings are not
signatures, label truth or engineer approval. Operation-level offsets remain
intermediate reversal data; only final localization describes final textual spans.

Default engine 0.1 retains its historical text-only route-map `partial` result;
JunOS engine 0.2 remains unchanged. This feature does not reserialize old samples,
increase the real corpus, train or qualify a detector, activate a model, or extend
native/model patch and network-review support. Generated formal status remains
`not_run`; vendor syntax and network behavior are explicitly unchecked.

The [owned functional report](evaluation/owned-cisco-route-map-order.json) separates
installed execution, software regression checks and historical compatibility from
unperformed device, model-quality and network qualification.
