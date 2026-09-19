# Authored laboratory scenarios

`authored-laboratory-0.1.0` provides twelve structurally different synthetic
reference configurations: Cisco IOS and JunOS set syntax for each of six
hypothetical network scenarios. They are original repository fixtures, not
third-party downloads, equipment exports, verified healthy configs or real
confirmed anomalies. No external dataset license has been inferred or approved.

| Scenario | Distinguishing structure |
|---|---|
| Static branch | Routed interface and default static route |
| BGP edge | External peer, autonomous system and router ID |
| OSPF core | Loopback, routed link, passive-interface behavior |
| Access switch | Two VLANs and separate access ports |
| Distribution trunk | Three VLANs and a trunk with allowed members |
| Filtered router | ACL/filter declarations, prefix list and discard route |

AAA, SSH, NTP and Syslog provide shared management controls in different relative
positions. Scenario pairs are comparable parser fixtures, not a claim of complete
cross-vendor semantic equivalence. ACL declarations are not necessarily bound
to interfaces; these references must not be deployed as security baselines.

## Provenance and boundaries

The versioned templates live in `ml/datasets/laboratory.py`. Hostnames pass through
the existing topology-scoped sanitizer. The deterministic pseudonymization key
is public and restricted to these already synthetic fixtures, never private
input. Addresses use documentation ranges. Capture timestamps are synthetic
ordering metadata, explicitly identified as such in the audit.

Each Cisco/JunOS pair shares a network/site identity so the splitter cannot put
the same scenario in different partitions. Default deduplication retains all
twelve candidates. Current allocation is:

- train: eight configs, static branch/BGP/OSPF/access scenarios;
- validation: two distribution-trunk configs, one per vendor;
- test: two filtered-router configs, one per vendor.

These represent six **hypothetical scenarios and zero independent real networks**.
Common management structure still crosses partitions. Role/scenario diversity
is not proof of generalization or a substitute for dataset scale targets.

## Audit bundle

```powershell
python -m ml.datasets.laboratory --output artifacts/authored-laboratory-v1
```

The new directory contains sanitized config files, records with provenance,
deduplication and split reports, and a syntax/mutation audit. Existing paths are
not overwritten. An `.incomplete` marker remains if writing is interrupted.
This is a generated fixture snapshot, not a replacement for the reviewed-source
import workflow or the integrity-checked dataset artifact format.

All twelve fixtures currently parse with zero warnings and zero unparsed
fragments. AAA-disable and Telnet-enable mutations apply to each. Routing, VLAN,
ACL and other mutations apply only to appropriate scenarios; the audit lists
their coverage. Syntax and mutation checks include the test fixtures for fixture
correctness, but no test model predictions are computed. Parser acceptance is
not hardware, Batfish, reachability or security validation.

## Initial training measurement

```powershell
python -m ml.training.laboratory_smoke --output artifacts/laboratory-localizer-v1
```

This trains a fresh train-only BPE/compact MLM, followed by the existing frozen
line head with stable input normalization. Only AAA/Telnet mutation types are
used in this training run; the wider mutation catalog is audited, not trained.
The optional reference-comment augmentation and train-reference threshold are
not used. The threshold remains 0.5. The output stores the model, split artifact
and validation diagnostics. Test scores remain unevaluated.

On six original validation examples (two references plus four mutated variants):

- four changed lines found, zero missed;
- nineteen false-positive lines;
- changed-line precision 0.1739, recall 1.0, F1 0.2963;
- both reference configurations receive alerts.

This is a more structurally diverse development check, **not an improvement
claim** or an independent real-world estimate. Comparing its scores directly
with the earlier one-device fixture would conflate model and dataset changes.
The actual corpus remains tiny, and the model still needs better discrimination
before production integration.
