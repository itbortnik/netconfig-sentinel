# Unseen mutation-family diagnostics

The lexical baseline is fitted once on AAA-disable and Telnet-enable examples.
`unseen-mutations-0.1.0` then creates other applicable mutation families, without
refitting vocabulary, IDF, coefficients or threshold. This tests whether success
on those two lexical patterns transfers to structurally different changes.

## Separate kinds of novelty

Results retain two distinct parent partitions:

- train parents: familiar original configurations, but mutation families not
  used as positive training examples;
- validation parents: unseen parent scenarios and unseen mutation families.

These are development diagnostics, not an independent test. Train-parent scores
must never be described as unseen-network performance. The test partition is
not parsed, mutated or scored; its recorded hashes are used for collision checks.

Novel examples preserve parent provenance and partition membership. Requests
that are not applicable are counted per family/partition, not silently counted
as successful negatives. Parser validation failures abort the run. Deletion-only
examples are excluded from current-line localization and reported separately.
Missing families have no evidence of either success or failure. All formatting
variants remain dependent copies, not additional independent devices.

```powershell
python -m ml.training.unseen_mutations --output artifacts/unseen-mutations-v1.json
```

The output is a new local JSON file containing the known-family validation
result, novel-family results by parent partition, per-family/per-vendor/per-variant
metrics and line-level cases. Both novel reports carry the same fitted model hash.
No production detector or training defaults change.

## Initial measured result

With threshold 0.5, on original texts only:

| Parent partition | Found changed lines | False-positive lines | Missed changed lines | Deletion-only examples excluded |
|---|---:|---:|---:|---:|
| Familiar train scenarios | 0 | 9 | 10 | 12 |
| Validation scenarios | 0 | 2 | 2 | 2 |

The scored novel families on train parents include BGP remote-AS mismatch, OSPF
area changes, VLAN mismatch, access/trunk mode changes and conflicting IPs. The
validation trunk scenario supports mode changes; the ACL scenario remains in
test and is deliberately not scored. Deletion exclusions cover applicable
missing-neighbor, removed-route and NTP/Syslog-removal examples.

The earlier known-family result (four detections, two false positives, zero
misses on original validation) therefore does **not** establish a general anomaly
detector. Token patterns for AAA/Telnet do not determine whether an otherwise
valid AS, area or VLAN value is correct. Contextual expectations, peer baselines,
policy constraints and more representative training evidence remain necessary.
The lexical model remains a narrow comparison baseline, not a replacement for
the hybrid detector architecture.
