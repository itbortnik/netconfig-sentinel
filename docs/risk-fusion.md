# Risk fusion v1

Risk fusion combines completed detector signals into one auditable assessment.
It is a transparent formula, not a learned classifier, and it never changes an
individual finding's severity, confidence, or anomaly score.

## Inputs and availability

Supported sources and configured weights are:

| Source | Weight |
|---|---:|
| deterministic policy | 0.35 |
| formal verification | 0.30 |
| exact peer baseline | 0.15 |
| Isolation Forest | 0.10 |
| Config Transformer | 0.10 |

Callers must list the detectors that completed. A completed detector with no
findings contributes a score of zero. An unavailable detector has no score;
its weight is redistributed proportionally across available sources and this
is recorded as a limitation. Verification completion is represented by an
explicit impact value rather than by a detector flag.

## Formula

For each detector, the strongest finding signal is:

```text
max(severity_score, anomaly_score) * confidence
```

Severity scores are `info=0.10`, `low=0.25`, `medium=0.50`, `high=0.75`, and
`critical=1.00`. Verification maps no adverse impact to `0.00`, policy
regression to `0.75`, and loss of reachability to `1.00`.

Available signals use normalized effective weights:

```text
effective_weight = configured_weight / sum(available configured weights)
fused_score = sum(raw_score * effective_weight)
```

Risk bands are `low < 0.25`, `medium < 0.50`, `high < 0.80`, and `critical`
from `0.80`.

## Safety guardrails

- A critical deterministic policy finding sets a minimum score of `0.90`.
- Verified loss of reachability sets a minimum score of `0.95`.

These guardrails prevent a low-confidence statistical signal from reducing a
critical formal result to a low risk. Every applied guardrail is included in
the assessment.

## Auditability and limitations

`RiskAssessment` contains a stable ID, the raw and effective weight for every
source, contributing finding IDs, applied guardrails, missing-source
limitations, and formula version `risk-fusion-0.1.0`.

The weights and bands are initial engineering defaults, not calibrated quality
claims. They must be evaluated and later replaced or recalibrated using
isolated labeled validation data and reliability metrics.
