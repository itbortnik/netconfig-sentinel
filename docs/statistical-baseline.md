# Statistical baseline

The first statistical control model uses scikit-learn Isolation Forest over a
fixed vendor-neutral feature schema. It complements exact peer consensus and
policy rules; it does not override either detector.

## Training contract

Training accepts configurations from exactly one peer group:

```text
vendor + platform + device_role + site_class + service_profile
```

At least eight configurations are required by default. Training is
reproducible for the same inputs and parameters: the random seed is explicit,
the feature order is versioned, and the estimator runs with one worker. Model
metadata records the scikit-learn version, sample count, contamination,
estimator count, peer key, training score range, feature medians, and robust
diagnostic scales.

## Structured features

Schema `structured-features-0.1.0` contains 33 numeric values covering:

- SSH, Telnet, AAA, SNMP, NTP, and Syslog state or counts;
- interface, address, access-port, and trunk counts;
- VLAN, ACL, ACL-rule, and prefix-list counts;
- static-route counts, discard routes, and default routes;
- BGP presence and neighbor-state counts;
- OSPF process, area, and passive-interface counts;
- parser confidence deficit, warnings, and unsupported fragments.

Feature extraction also retains source locations for diagnostic localization.
The schema deliberately excludes raw secrets, hostnames, IP values, and full
configuration text.

## Finding interpretation

The estimator emits a finding only when its prediction is `-1`. The reported
anomaly score normalizes the raw sample score against the score range observed
during training. Confidence is capped by parser confidence and grows linearly
to its maximum at 50 training samples.

Up to three features with the largest median-relative deviations are attached
as diagnostic context. These deviations are not tree attributions and must not
be described as the reason the forest made its decision. A human should review
the result together with policy findings, the exact peer baseline, and change
history.

## Current limitations

- The fitted estimator is in memory; safe persistence and registry integration
  are not included in this slice.
- No production-quality metric is claimed from unit fixtures.
- Thresholds and contamination require evaluation on isolated real and
  synthetic test sets before operational use.
- High-dimensional semantic configuration content is intentionally left for
  the later Transformer stage.
