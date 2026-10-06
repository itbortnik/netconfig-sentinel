# Offline evaluation and calibration

`ml.evaluation` evaluates recorded predictions against reviewed annotations.
It does not change findings, detector confidence, severity, online risk, registry
activation, patch status or verification. It requires no network service, model
download or additional dependency. The generic metric and calibration commands
do not require PyTorch; only the frozen-probe adapter uses the training extra.

## Inputs and evidence

`EvaluationBatch` contains a versioned `EvaluationProtocol` and bounded cases.
The protocol identifies the model and optional tokenizer, policy, documents and
calibration by hashes/versions, the reviewed dataset manifest, threshold policy,
ordered category catalog and thresholds. Every case includes source-review and
annotation hashes, opaque source/family/device/site/network identities, origin,
vendor/role, binary truth, category truth and corresponding scores. Optional
fields contain unknown-anomaly annotation/ranking score, current-file line
annotations, measured analysis time and parser command-line coverage.

No configuration text, credentials, paths or document prose belong in this
contract. Hashes are not authorization, anonymization or signatures: operators
must independently review the source permissions, grouping, annotations and
their referenced artifacts. Treat local prediction and calibration files as
confidential; identifiers and hashes can still be linkable. Do not publish
real-data artifacts automatically.

`target_semantics=confirmed_anomaly` means reviewed anomaly labels;
`injected_mutation` means only that an operation was injected. An unmodified
synthetic parent is **not** an assertion that a device is healthy. The latter
semantics cannot populate the `real_confirmed` cohort. A real case also requires
review and annotation hashes; caller-supplied metadata is not independently
attested by this evaluator.

Cases are limited to 20,000, categories to 64, the prediction matrix to one
million values and localization to one million source lines. Role slices are
bounded at 64. JSON input is capped at 64 MiB; duplicate keys, unknown fields,
nonfinite/out-of-range scores, duplicate configuration hashes, inconsistent
labels and anchors are rejected. Revalidation catches bypassed model copies.

## Split discipline and missing cohorts

An `independent_test` must be disjoint from every recorded training, model/
threshold-selection and calibration exposure in source hash, near-duplicate
family, device, site **and** network. Training/selection/calibration exposures
must themselves be disjoint. The evaluator checks the supplied keys, not the
correctness of deduplication or temporal provenance; use the existing dataset
split audit to establish those facts.

`validation_diagnostic` may reuse selection/calibration examples but never
training entities. Such reuse is explicitly labeled `independent_test=false`.
The unseen-site slice is derived from all recorded exposures, not a manually
supplied flag. All origins have separate summaries, vendor/role and unseen-site
slices. Missing `synthetic`, `laboratory` or `real_confirmed` cohorts have
`status=missing` and no fabricated scores. Missing vendor results are `null`.
There is no mixed synthetic/real headline metric and no automatic quality pass.

## Metric definitions

- Binary anomaly detection and one-vs-rest categories: TP/FP/FN/TN, precision,
  recall and F1 at the recorded strict `score > threshold` decision boundary.
  Category scores are independent thresholds, not a multiclass argmax.
- Macro-F1 averages defined category F1s and records the number of defined
  classes. Undefined denominators are `null`, not a perfect score or a made-up
  zero. A class with a missed positive or false positive has defined F1 zero.
- Both noninterpolated average precision and trapezoidal PR-AUC are named
  separately; they can differ, especially with ties. Ranking metrics require
  both positive and negative annotations.
- Unknown-anomaly precision@K uses only cases with explicit unknown truth and
  scores; annotated/scored counts make missingness visible. Boundary ties use
  fractional expected positives, independent of case-ID order. If fewer than K
  cases are scored, the result is `null`, not precision at a smaller K.
- Localization uses current-file positive/scored/predicted/ignored line sets.
  Unscored positive lines remain false negatives. Unscored eligible lines and
  missing annotations are counted. Deletion-only changes have no invented
  positive current-file anchors and are excluded with a separate count.
- False positives per device count binary false-positive **configuration
  alerts** divided by unique devices; repeated versions can produce more than
  one alert/device. The per-configuration rate is also reported. This is not
  deduplicated operational alert volume.
- Probability scores have equal-width binary reliability bins, ECE and Brier
  score for detection and each category. Empty bins are retained; probability
  one belongs to the final bin. Ranking scores have no probability calibration
  metrics. A small ECE alone does not prove good discrimination or calibration.
- Time reports measured/missing counts, mean, median, linear-interpolated p95
  and maximum. `latency_scope` states the producer's measured interval; no
  end-to-end, hardware or throughput claim is inferred.
- Parser coverage is recognized/significant command lines, with micro and
  macro averages and missing/zero-denominator counts. `parser_coverage()` uses
  the existing vendor comment lexer and unknown-line anchors, bound to the
  exact source hash. It excludes blanks/comments but includes structural JunOS
  braces. This is not parser confidence, semantic completeness or syntax proof.

Definitions follow [average precision](https://scikit-learn.org/1.8/modules/generated/sklearn.metrics.average_precision_score.html)
and the [probability calibration guide](https://scikit-learn.org/stable/modules/calibration.html).
The local implementation additionally records denominators, ties and origins.

## Running the report

From the repository root, after the normal development install:

```powershell
python -m ml.evaluation.cli --input artifacts/predictions.json --output artifacts/metrics.json --reliability-svg artifacts/reliability.svg
```

Input can be produced from any supported detector by an explicit exporter
following `ml/evaluation/contracts.py`. Different models should use the same
annotations, exposures and decision protocol for a meaningful paired comparison;
this tool does not manufacture predictions for unavailable detectors.
The SVG shows binary anomaly reliability separately by origin. It renders fixed
labels and numerical coordinates only, never untrusted prose or raw identifiers.
CLI errors do not echo private input. Outputs must be new files with existing
parent directories; existing results are not overwritten.

For the existing authored-fixture classifier and compatible localizer:

```powershell
python -m ml.evaluation.probe_validation --probe artifacts/mutation-probe-v1 --localizer artifacts/line-localizer-stable-v1 --output artifacts/probe-evaluation-v1
```

The adapter verifies the selected encoder and train/validation fingerprints,
class order and optional localizer binding, runs actual CPU inference and
parsing, then saves predictions, metrics and SVG. Temporary thread count is
restored. Selection data stays diagnostic; no test set is opened for tuning.
Unknown-anomaly quality is absent when no unknown cases are annotated.

## Calibration without test leakage

`fit_calibration()` accepts only fresh probability scores under a diagnostic
protocol whose cases are disjoint from training **and selection**. This is a
separate calibration partition, not reuse of validation used to select epochs.
Every detection/category channel needs at least ten positive and ten negative
cases by default. Insufficient support, ranking scores, previous calibration or
test purpose are rejected, not replaced with an identity-success artifact.

Binary temperature scaling searches a recorded bounded grid minimizing NLL;
the identity transform is included. Ties favor the identity/nearest identity.
Zero/one probabilities stay endpoints; NLL alone clips at `1e-12` for numerical
safety. It is a binary per-channel transform, **not** multiclass softmax
temperature scaling; independent category probabilities need not sum to one.
NLL must not worsen on the fitting partition, which says nothing about test.

Each channel separately selects a threshold on the recorded grid by F1, then
precision, then the highest tied threshold. These are validation choices, not
business-cost-optimal risk thresholds. The artifact records support, fit-cohort
counts, temperatures, thresholds, NLL, selection F1, model/corpus bindings and
calibration exposures. Its canonical hash identifies the exact artifact.

```powershell
python -m ml.evaluation.calibration_cli fit --input artifacts/calibration-predictions.json --output artifacts/calibration.json
python -m ml.evaluation.calibration_cli apply --input artifacts/test-predictions.json --calibration artifacts/calibration.json --output artifacts/calibrated-test.json
python -m ml.evaluation.cli --input artifacts/calibrated-test.json --output artifacts/calibrated-metrics.json --reliability-svg artifacts/calibrated-reliability.svg
```

Apply rejects changed model/tokenizer/corpus/classes or omitted training/selection
exposure, repeated calibration and test overlap. It transforms scores and records
the chosen thresholds/exposures without changing truth or model weights. Reusing
the fitting cases is allowed only as a labeled diagnostic, not a held-out pass.
The current three-example selection fixture cannot fit a valid calibration
artifact and has not been used to claim calibrated real-world probabilities.

## Measured example, not acceptance

The [measured synthetic report](evaluation/synthetic-probe-validation.json) and
[reliability SVG](evaluation/synthetic-probe-reliability.svg) were produced by
actual local frozen-probe/localizer inference on 2026-10-06. There are only three
selection configurations of one Cisco device. JunOS, laboratory, confirmed-real
and independent-test results are absent. Fixed 0.5 category thresholds give
macro-F1 **0** despite AP 1 on this tiny ordering; localization precision is
0.4, recall 1, F1 about 0.571. Binary anomaly F1 is 0.8 with one false alert on
the unmodified reference. Low ECE on three examples is not a calibration pass.

The report preserves model/input/threshold hashes and measured parsing+inference
time, which is hardware-dependent. It is not a benchmark of throughput, a
baseline superiority claim, a representative vendor evaluation or production
quality. A separate annotated calibration partition and authorized real,
entity-isolated test cohorts are still required for those conclusions.
