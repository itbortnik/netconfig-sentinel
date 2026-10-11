# Numbered standard IPv4 ACL facts

The Cisco IOS adapter accepts complete, non-indented global rows:

```text
access-list 7 deny host 192.0.2.7
access-list 7 permit 198.51.100.0 0.0.0.255
access-list 7 deny any
```

This implements the ACL ingestion/normalization/provenance slice of requirements
4, 9, 11.1 and 21. It does not add a new policy, schema, attachment model,
effective packet-filter evaluator, or vendor/device syntax verdict.

## Supported semantics and refusals

Standard IPv4 numbers are 1–99 and 1300–1999. The source operand is exactly
`any`, `host IPv4`, or `IPv4 [wildcard]`. An omitted wildcard means `/32`;
contiguous low-order-one wildcard bits become a CIDR prefix. All-one wildcard
becomes literal `any`, including when source address bits are nonzero. These
standard ranges and implicit-host semantics follow the
[Cisco IOS XE 16.9 configuration guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-16-9/sec-data-acl-xe-16-9-book/sec-create-ip-apply.html).
The contiguous-only constraint is our representation limit, not a claim that
other wildcard masks are invalid Cisco syntax.

Numbers use canonical ASCII decimal spelling; leading zeros are conservatively
refused. Extended numbers, IPv6/CIDR operands, remarks, logging/other options,
sequence operands, deletion and dynamic/object-group forms remain whole unknown
commands. Unsupported rows never create an empty ACL or a partial permit fact.
Indentation inside a submode does not make a global numbered row valid.

Repeated/interleaved numbered rows share one standard IPv4 `AclConfig` per number,
in first-appearance order. Rules retain source order and repeated occurrences;
no sequence number is invented. Each rule binds its original line and text hash;
ACL name provenance contains all supported contributing rows. If the same numeric
IPv4 identifier appears in an `ip access-list` header anywhere in the input, its
global numbered rows remain unknown, regardless of ordering or leading-zero
header spelling. This avoids inventing mixed-form sequencing/edit semantics.
IPv6 names use a separate namespace. The named adapter behavior is unchanged.

## Policies, coverage and history

Existing `acl.unrestricted_permit` evaluates a configured `permit any` with the
exact rule anchor. A preceding deny is retained, not evaluated for shadowing.
This finding does not establish attachment, reachability, or effective passage.
The catalog still contains 30 unique policies; no versioned policy source or
historical finding is rewritten.

Fresh uploads expose the new canonical facts and actual accepted/unparsed counts
through the existing API and interface. Unsupported siblings stay unknown and
keep partial-analysis/risk suppression. The source-line census algorithm and
its accounting version are unchanged; the version is not a frozen grammar claim.
Previously saved canonical snapshots, findings and coverage are read as stored,
not reparsed. ML structural segmentation/tokenization/targets are separate from
this parser and are not upgraded or retrained by the change.

Authored unit checks cover range/operand boundaries, inverse-mask refusal,
all-source equivalence, order/repeats, contexts, mixed namespaces and exact hashes.
Upload/analysis/restart checks cover configured findings and partial gates.
Existing golden inputs remain unchanged. Approved upstream configurations stay
private; any measured corpus delta is functional parser evidence, not independent
real anomaly labels, model quality, physical network independence or formal safety.

The [paired installed diagnostic](evaluation/owned-numbered-standard-acls.json)
uses the same 415 retained approved inputs, without another acquisition. It adds
23 accepted rules in nine inputs; another input gains only an unsupported-entry
warning. Accepted/unparsed source lines change from 1387/3738 to 1410/3715 with
the same 5125-command denominator. Partial inputs change from 389 to 388; this
fresh measurement does not rewrite the historical intake's 389 partial inputs.
There is one additional configured unrestricted-permit finding. The unchanged
Stage A corpus audit and Stage B source/annotation/exposure gates still validate;
no model inference, training, activation or quality evaluation was performed by
this corpus diagnostic. Existing structured feature values may change on freshly
parsed ACL inputs; historical canonical/feature snapshots are not recomputed.
In this paired diagnostic, 44 existing fresh findings have only increased parser
confidence; their IDs, severity and evidence are unchanged. This is a consequence
of fewer unknown commands, not new detector calibration or a historical update.
