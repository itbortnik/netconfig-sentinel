# Versioned deterministic policy catalog

`policy-rules-0.7.0` contains 30 distinct requirements. Vendor-specific evaluation
shares the same requirement ID; encoding variants are not counted as separate
rules. All have severity, declared platforms, remediation, internal documentation
references and positive/negative tests through the supported parser slice.

| Area | Requirements |
| --- | ---: |
| Management identity, AAA, SSH, Telnet | 5 |
| SNMP, NTP, Syslog | 4 |
| ACL/control-plane access | 4 |
| BGP, OSPF, static routing | 6 |
| Interfaces/VLANs | 6 |
| Explicit local-account metadata | 5 |
| Total | 30 |

New account rules check explicit passwordless access, type-0 storage, reversible
type-7 passwords, legacy type-4/5 secrets and shared explicitly assigned JunOS
UIDs. They never include credential values, infer implicit encodings or validate
login. The routing additions check local-address and non-unicast static next hops.
Interface additions check undefined explicit VLAN references, Cisco native-VLAN
filtering and repeated host addresses on different non-disabled interfaces.

These are internal review requirements, not a universal vendor compliance
standard. Intentional native-VLAN filtering, anycast, dynamic VLAN provisioning
and unsupported VRFs/inheritance require engineering judgment. Findings retain
these limitations. The engine evaluates supported facts, not operational state
or reachability; `anomaly_score=0` is not severity, risk or a network-safety pass.
Incomplete parsing still suppresses the aggregate API risk.

The immutable `POLICY_CATALOGS` registry also retains the unchanged 20-rule
`policy-rules-0.6.0` definitions. `evaluate_policies(..., catalog_version=...)`
uses only the selected reviewed version; unknown versions, duplicate selections
and rules from another version are rejected. Local explanations recompute a
finding under its recorded catalog version. Existing saved analyses are not
rewritten or rescored. Unsupported older versions are not silently upgraded.

The reviewed-document catalog resolves references for either supported policy
version from the current bundled documents and binds current document/chunk
hashes. It does not claim to archive the complete historic document set or model
weights. Source/analysis/history fingerprints and human review remain separate
from current document retrieval.
