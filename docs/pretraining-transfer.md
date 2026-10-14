# Joint configuration pretraining -> supervised heads

The bounded local `train_multitask()` trainer accepts either an existing trusted
MLM checkpoint or a native `PretrainingResult` from the project's six-objective
training path. The objective-backed path uses the actually trained nested
configuration encoder for every block/line feature. It freezes a deep copy of
the entire Stage A model, including reconstruction and auxiliary heads, then
trains only the residual feature adapter, block pooler and supervised heads.
The original model's weights, mode, gradients and process random/thread state
remain unchanged. This is not attention LoRA, an external foundation-model
download, full encoder fine-tuning or online detector activation.

## Source and exposure checks

Callers supply the original audited `DatasetSplitResult`, reviewed supervised
examples and the exact `SemanticPair` labels used by Stage A. Before Stage B,
`validate_objective_source()` revalidates report/tokenizer/model consistency and
regenerates Stage A targets using its recorded seed and construction budgets.
Train/validation source and objective fingerprints, source/target counts,
semantic scope and label origins must agree. Changed truth/review hashes, missing
or reordered label exposure, a different corpus or a test/cross-partition pair
fail instead of silently switching to a legacy path. Enabled/disabled Stage A
terms retain their original report; this step does not invent losses or labels.

The new `multitask-training-0.2.0` report retains an explicit
`objective-source-binding-0.1.0`: full Stage A model/report identity, original
split-manifest hash, exact semantic labels and their manifest hash. The split
manifest hash identifies the reserved test partition without making its texts
training features or using its labels. Stage A uses only non-test targets;
Stage B uses only train labels and validation-based epoch selection. Semantic
pair scope does not establish whole-configuration equivalence or reachability.

Legacy `multitask-training-0.1.0` and its MLM encoder subdirectory remain readable
without adding transfer fields to old reports. A legacy run rejects supplied
semantic labels instead of ignoring them. Objective runs retain their native
`config-objective-pretraining-0.1.0` encoder bundle, not a fabricated MLM report.
No speculative format detection or fallback crosses these boundaries.

```python
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_training import train_multitask

result = train_multitask(
    audited_splits, trusted_objective_result, reviewed_examples,
    semantic_pairs=original_reviewed_pairs,
    head_policy=HeadPolicy(classes=("management.telnet",)),
    loss_weights=LossWeights(severity=0),
)
```

Use a zero task weight only when intentionally disabling that output. Unknown
labels remain excluded rather than becoming negative labels. Severity requires
reviewed severity labels, never policy severity or a mutation recipe.

## Saved model and diagnostics

The existing non-overwriting model layout remains `encoder/`, `heads.json` and
`heads.sha256`; native encoder loading follows the recorded report version.
The full Stage A weights (including auxiliaries) and report are bound to the
new provenance, so auxiliary-only drift is also rejected. In-memory CPU tensor
finiteness/dtype, architecture and tokenizer checks precede transfer; feature
extraction requires all nested modules in evaluation mode. Prediction/save/load
revalidate source binding and supervised encoder/tokenizer/count bindings.
Strict inventories, bounded files, checksums and tensor-only loading still apply.

The metric adapter additionally requires the original split manifest and
regenerates source exposure using retained pair labels. It remains validation
diagnostics on the epoch-selection corpus, not an independent test. The
generic evaluator can report separate real cohorts only when actual reviewed
real examples are supplied through an appropriate evaluation protocol.

Hashes identify trusted artifact contents, not a publisher, authorization,
label truth or a hostile operator's complete rewrite. Retain and review the
original authorized corpus/annotations. Training bundles contain confidential
model artifacts and need OS access control; they are not encrypted API storage.
No optimizer resume, external foundation ingestion or large-corpus training is
added by this bridge.

## Measured authored demonstration

```powershell
python -m ml.training.pretraining_transfer_smoke --output artifacts/joint-transfer-v1
# Reuse a trusted six-objective bundle of these exact authored fixtures:
python -m ml.training.pretraining_transfer_smoke --source-model artifacts/pretraining-objectives-v1 --output artifacts/joint-transfer-v2
```

Both commands refuse existing output. This specific smoke always uses the owned
24-configuration/12-network fixture and its reviewed static-route pair labels;
`--source-model` does not authorize arbitrary corpus substitution. Output metrics
are sibling files, outside the strict model-directory inventory.

The [training report](evaluation/pretraining-transfer-training.json) and
[validation report](evaluation/pretraining-transfer-validation.json) were
generated locally on 2026-10-07. Stage A has 52,725 parameters and ten epochs;
Stage B has 3,993 trainable parameters, 48 train views and 12 validation views
across four validation devices. It trains anomaly/category/localization/embedding
terms for a single authored Telnet recipe; severity is explicitly disabled.
The original reserved four test configurations are untouched. Leading-blank
views and injected variants are not new independent networks or real anomalies.

At fixed 0.5 thresholds, anomaly/category F1 and line recall are **0**. No positive
is predicted: zero false positives therefore does not establish useful detection.
The Cisco validation views contain only references; positive injections in this
fixture are JunOS-only. There are no real-confirmed, independent-test,
unknown-anomaly or fitted-calibration results. These measurements establish a
working source-bound training/save/load pipeline, not improved anomaly quality,
baseline superiority, cross-vendor generalization or production readiness.

## Approved train-only source fixtures -> supervised heads

Этот checkpoint теперь также имеет explicit [двухмодельное сравнение с лесом](paired-detection-comparison.md#fixture-backed-native-03-и-тот-же-контрольный-лес)
на исходной authored selection, без нового fit native heads или изменения порога.
Это functional comparison; fixed-threshold F1 остаётся 0, real/independent quality
и физическая изоляция по-прежнему не подтверждены.

The separately versioned `multitask-training-0.3.0` path accepts an actual
`FixturePretrainingResult` and its retained private `FixtureTrainingCorpus`.
It does not require that this unknown-metadata collection was selected on the
downstream validation corpus. Neither a legacy MLM nor a six-objective report
is fabricated. Existing 0.1/0.2 checkpoints and their numerical training paths
remain unchanged; unsupported versions still fail explicitly.

`validate_fixture_source()` rechecks source permissions, complete imported
inventory/current content/deduplication, model/tokenizer/tensor consistency and
the recorded Stage A reconstruction targets. Its source binding retains actual
model/report/corpus hashes and a downstream manifest/exposure audit. Physical
network, device, capture time and confirmed anomaly metadata remain unknown;
`physical_pretraining_isolation_proven` is always false.

Before fitting, every upstream intake member, including duplicates and structural
holds, is compared with every unique downstream content item: all recorded split
representatives (including reserved test) and supplied train/validation derivatives.
Checks cover source ID, raw/sanitized/normalized hash, abstracted template and
exhaustive token Jaccard similarity. Identical downstream texts preserve **all**
supplied members' source/raw provenance, not only the first member. Discarded
downstream duplicate metadata not present in this split/derivative input is not
invented or audited. This bounded check does not establish exhaustive original
downstream provenance, independent physical identity or chronology.

Any source/template/content match against validation or reserved test refuses the
whole run. Train overlap is allowed but counted. Template matches are conservative
and can refuse generic shared templates; no convenient target subset is selected.
Default limits are 200,000 comparisons and Jaccard >= 0.82, recorded explicitly;
budget overruns fail instead of truncating. Test text is used only for overlap
checking, never encoded as a feature or used with labels for epoch/threshold tuning.

The existing nested-encoder feature extractor, frozen deep copy, residual adapter,
pooler, losses, optimizer, validation epoch selection and saved bundle are shared.
Training/prediction/save/load bind the whole Stage A state, including disabled
auxiliary heads. The existing validation metric adapter also requires the retained
private corpus and regenerates the exact fitted exposure and annotation bindings.
Neither missing Stage A device/semantic labels nor Stage B severity labels are
manufactured. Since 2026-10-11, explicit [private registry admission](transformer-model-registry.md)
reuses that exact validator and requires all retained source/downstream inputs.
Its separately versioned model card preserves unknown physical isolation. The
registered format is supported by opt-in saved-analysis HTTP/UI and private
pre/post diagnostics, without risk fusion, calibration or production activation.
At the original 2026-10-10 transfer measurement these integrations were absent;
that historical measurement is not rewritten or counted as new quality evidence.

```python
result = train_multitask(
    downstream_splits, trusted_fixture_encoder, reviewed_examples,
    fixture_corpus=retained_private_fixture_corpus,
    head_policy=HeadPolicy(classes=("telnet_enabled",)),
    loss_weights=LossWeights(severity=0),
)
```

The explicit authored demonstration uses an independently pinned source bundle
and complete retained manifest/imports; it refuses existing output:

```powershell
python -m ml.training.fixture_transfer_smoke --source-model private/source-bundle --source-sha256 <full-pin> --manifest private/fixture-manifest.json --records private/imported-fixtures.json --output artifacts/new-fixture-transfer
```

[Measured transfer](evaluation/owned-source-fixture-transfer.json), 2026-10-10:
the actual 412-fixture reconstruction encoder feeds 3,993 trainable head/adapter
parameters, 50,603 total. The original 24 authored configs are re-sanitized for
this current content gate, not counted as new networks or real anomalies.
Their 16 train/4 validation/4 reserved-test configs yield 48/12 labeled formatting
and Telnet views. All 415 upstream members versus 64 unique downstream contents
produce 26,560 comparisons, with no observed overlaps. Physical independence
still remains unknown. Twenty predeclared epochs select epoch 20 by validation
loss (1.29161); the native fixture source remains unchanged. Save/load preserves
all predictions; an isolated installed package gives the same model identity.

At the fixed strict 0.5 threshold anomaly/category F1 and line recall are **0**;
four injected positives are missed, with no predicted positive. Anomaly AP is
0.81667 (trapezoidal PR-AUC 0.79583); category AP is 1 on these twelve selection
views. These are diagnostic ranking results, not fitted calibration or acceptable
detection. Positive injections are JunOS-only; Cisco views are references.
Real-confirmed, independent-test, unknown-anomaly and calibration-fit evidence
remain absent. No baseline superiority, corpus scale, cross-vendor quality or
online/production readiness follows from this transfer.

## Fixed optimizer-budget diagnostic

[Diagnostic 2026-10-11](evaluation/owned-fixture-optimizer-budget.json) varies
only the supervised optimizer budget: seeds 17/23/41, each at 20 and 200
full-batch AdamW steps. The six combinations, learning rate 0.01, task weights,
strict 0.5 thresholds and reporting of **all six** runs were fixed before fitting.
There is no best-seed selection, threshold fitting, new Stage A training, model
download, corpus/annotation replacement or online activation. The original
seed-17/20-step run reproduces the historical model identity exactly.

The existing API accepts these settings through
`FineTunePolicy(seed=seed, epochs=budget)` in `train_multitask()`, with
`authored_transfer_splits()`, the same Telnet `authored_supervision()`, retained
approved fixture corpus, `HeadPolicy(classes=("telnet_enabled",), max_examples=128)`
and `LossWeights(severity=0)`. Each epoch is one full-batch update, not a pass
with multiple minibatch optimizer steps. The minimum weighted validation loss
still selects the saved epoch; detection F1 does not select it.

| Seed | Executed steps | Selected epoch | Anomaly/category F1 @ 0.5 | Line recall @ 0.5 |
| --- | ---: | ---: | ---: | ---: |
| 17 | 20 | 20 | 0 | 0 |
| 17 | 200 | 38 | 0 | 1 |
| 23 | 20 | 20 | 0 | 0 |
| 23 | 200 | 68 | 0.4 | 1 |
| 41 | 20 | 20 | 0 | 0 |
| 41 | 200 | 42 | 0 | 0.5 |

Metrics belong to the restored selected checkpoint, **not** the final epoch 200.
For seeds 17/23/41, weighted validation loss rises from selected minima
0.943/0.712/0.985 to final 6.129/3.129/4.353 while training loss falls below
0.0005. This divergence is consistent with late overfitting on this tiny selection;
it does not establish a unique explanation of the original fixed-threshold failure.

Within each seed pair, all first twenty train/validation component losses are
exactly equal, as are encoder/tokenizer, annotation fingerprints, source exposure,
head settings and task weights. The report preserves first/selected/final losses,
positive/negative score ranges and each complete outcome. All six save/load checks
preserve every train/selection prediction; previous source and reports are unchanged.
Execution uses an isolated installed package with 230 byte-equal runtime files.
The same retained actual forests are rescored on all twelve shared cases, with
numeric parity and F1 zero; they are not fitted again or assigned neural heads.

This shows sensitivity to training budget, not a unique cause or a general repair.
Two longer runs still miss all four positives; the other detects only one. Better
line recall on four positive lines among 98 does not qualify detection. All
positives remain JunOS-only, with possible vendor/recipe/length/format shortcuts.
The four selection devices and their twelve views are reused epoch-selection
data, not an independent test. Raw ECE/Brier are diagnostic, not calibration fit.
Reserved test text is used only in the existing content-overlap gate, without
features, labels or tuning. Real-confirmed, Cisco-positive, independent unknown-site,
severity and production quality remain unqualified. There is no accepted winner.

## Explicit bilateral Telnet scenario

The opt-in `bilateral-telnet-0.1.0` adds positive Cisco supervision to the owned
fixture-transfer demonstration. The default remains `legacy-telnet-0.1.0`:
the complete old split, 48/12 train/selection views, protocol fields and saved
checkpoints are not reinterpreted. This is a versioned authored scenario, not
an importer of additional real configurations or an independent dataset.

```powershell
python -m ml.training.fixture_transfer_smoke --source-model private/fixture-encoder --source-sha256 <full-pin> --manifest private/fixture-manifest.json --records private/fixture-records.json --owned-scenario bilateral-telnet-0.1.0 --output artifacts/new-bilateral-transfer
```

Each Cisco authored parent gains `line vty 0 4` / `transport input ssh` before
sanitization, so the existing generator can apply its Telnet recipe. JunOS
parent text is unchanged. All parents have a distinct scenario source ID and
raw SHA/byte counts derived from their actual authored pre-sanitizer bytes;
sanitized hashes are recomputed. Entity, capture-time and 16/4/4 partition
memberships remain the same. Existing sanitization, deduplication, splitter,
source-exposure, annotation and reserved-test checks are not relaxed.

The 24 authored parents still represent only twelve **hypothetical** network
labels. Sixteen train parents now yield 64 views: 16 positive and 16 negative
per vendor. Four selection parents yield 16 views: four positive and four
negative per vendor. The leading-blank views stay bound to their parents and
line coordinates. Four reserved parents produce no training/selection examples;
their text is used only in the existing overlap gate. There are no new
independent networks, confirmed anomalies, severity labels or semantic pairs.

[Actual installed diagnostic](evaluation/owned-bilateral-fixture-transfer.json)
uses the retained approved 412-fixture encoder and the unchanged default seed
17, 20 full-batch steps, loss weights and strict 0.5 thresholds. The minimum
weighted selection loss chooses epoch 20 (1.52670). All 415 retained upstream
members are checked against 84 unique downstream contents: 34,860 comparisons,
no observed overlap, and **unknown physical independence**. The encoder and
80 historical source/model/report files remain unchanged; save/load preserves
all 80 new predictions. Old and new installed packages also agree on the full
legacy input and all 60 predictions of the historical model.

The selected new model detects six of eight injections, with zero false
positives: anomaly F1 0.85714, AP 1. Cisco detects four of four positives; JunOS
detects two of four. Category F1 is 0.66667 (four of eight positives detected).
Line recall is still **0**, missing all eight positive lines among 148 eligible
lines. Raw ECE/Brier are not a calibration fit. The shared-case comparison fits
new forests only on the sixteen original new-scenario train parents, with F1
zero on exactly the same sixteen selection views.

The new parent context, class balance, view count and truth table differ from
legacy. This is **not** a paired legacy improvement or isolated causal proof
that a vendor shortcut was removed. Reused selection data, tiny authored
templates, formatting/recipe/length shortcuts and line-level imbalance remain
limitations. No independent-test, real-confirmed, vendor-syntax, formal safety,
online activation or production-quality gate is passed.

## Fixed bilateral line-head diagnostic

[Recorded diagnostic](evaluation/owned-bilateral-line-localization.json) examines
the **same selected bilateral checkpoint**, not another fit, threshold search or
independent test. Exact retained source/annotation/exposure validation precedes
feature extraction. All 32 train and eight selection positive current-file anchors
have encoded features and positive `_targets`; no encoded target is ignored in
this particular scenario. Batched and single-record line scores agree within
`atol=1e-7, rtol=1e-6`, and the selected epoch's validation localization component
is reproduced. Ninety-four retained source/model/report files remain unchanged.

| Scope | Positive / eligible lines | Positive score range | Line AP | TP / FN at strict 0.5 |
| --- | ---: | ---: | ---: | ---: |
| Train | 32 / 592 | 0.04215–0.06854 | 0.34029 | 0 / 32 |
| Selection | 8 / 148 | 0.04215–0.06810 | 0.42500 | 0 / 8 |
| Cisco selection | 4 / 84 | 0.04215–0.04916 | 0.20000 | 0 / 4 |
| JunOS selection | 4 / 64 | 0.04371–0.06810 | 0.66667 | 0 / 4 |

Configuration-level class balance does not balance line targets: positives are
only 5.405% of eligible lines in train and selection. The existing loss is the
mean unweighted BCE across eligible lines, not a class-balanced objective. At
the selected checkpoint, selection BCE is 0.18160: positive lines contribute
0.16211 and negative lines 0.01949 to that mean. Positive errors are present,
not masked or discarded. The validation localization component fell from
0.56656 after update one to 0.18160 after update twenty, while strict-threshold
recall at the saved checkpoint remains zero, including on train.

For context, the closed-form constant **train prevalence** score is 32/592 =
0.05405. It has BCE 0.21028 on these train/selection line targets and zero recall
at 0.5. This train-only numerical reference is not a newly fitted or activated
detector, a calibrated threshold, or a baseline-comparison winner. A lower BCE
does not by itself establish useful localization; the ranking also mixes both
classes. Stored per-vendor train/selection results distinguish AP from trapezoidal
PR-AUC. Train loss measured here is **after** the saved update; epoch reports store
train loss **before** each update and validation loss after it.

Ranking uses scores from the single-record prediction path exactly once, then
filters the same values for every global/vendor slice. An initial private
diagnostic instead recomputed sigmoid for each slice shape: floating-point tie
changes produced Cisco selection AP 0.17778 instead of 0.20000. Independent review
identified that metric-path error before publication. Both attempts are retained
with hashes in the evidence; no weights, truth or decision threshold changed.
Numerical `allclose` does not establish identical ties or ranking metrics. BCE
still uses the original full-batch logits to reproduce the saved loss component.

These checks rule out missing positive targets and batch-to-file score mapping
drift for this exact diagnostic. They do **not** isolate a unique cause among
class imbalance, shared objectives, frozen features, optimization and authored
template shortcuts. No class weights, loss weights, thresholds, model artifacts
or online decisions change. Reserved test features/labels remain unused;
calibration, independent localization quality and real-confirmed labels remain
open. A useful repair requires a separately fixed experiment or a reproduced
implementation defect, not post-hoc selection tuning presented as acceptance.

## Train-balanced bilateral line objective

The explicit intervention follows the preceding alignment diagnostic and
implements supervised localization rather than only reporting a hypothetical
repair. The default is still unweighted. The existing fixture smoke accepts
`--seed` and `--line-objective train-balanced` without a new training/evaluation
subsystem:

```powershell
python -m ml.training.fixture_transfer_smoke --source-model private/fixture-encoder --source-sha256 <full-pin> --manifest private/fixture-manifest.json --records private/fixture-records.json --owned-scenario bilateral-telnet-0.1.0 --seed 17 --epochs 20 --line-objective train-balanced --output artifacts/new-balanced-transfer
```

Use a new output for every arm/seed. This is native fixture format 0.4.
At the original measurement it was offline-only. Subsequent
[explicit registry/diagnostic selection](transformer-model-registry.md#explicit-train-balanced-format-04)
does not rewrite that run, select a winning seed or change the default model.

[Actual installed evidence](evaluation/owned-train-balanced-localization.json)
retains all six predetermined CPU fits: seeds 17/23/41 × unweighted/train-balanced,
20 full-batch AdamW updates per run. The protocol was frozen before fitting.
Each pair shares initialization seed, source encoder, policies, full downstream
truth table and strict `score > 0.5` decisions. The same 24 authored parents yield
64 train/16 selection views, not new data. Severity stays disabled. There are
32 positive and 560 negative eligible train lines: the fixed positive coefficient
is 17.5. Selection has eight positives and 140 negatives and does not determine
the coefficient. No reserved-test features/labels, threshold fit or calibration
fit are used. Epochs are selected by each arm's own recorded validation objective.

| Seed | Objective | Selected epoch | Line TP / FP / FN | Line F1 | Line AP | Anomaly F1 | Category F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 17 | Unweighted | 20 | 0 / 0 / 8 | 0 | 0.42500 | 0.85714 | 0.66667 |
| 17 | Train-balanced | 20 | 6 / 4 / 2 | 0.66667 | 0.75000 | 0.40000 | 0.40000 |
| 23 | Unweighted | 20 | 0 / 0 / 8 | 0 | 0.46245 | 0.50000 | 0.80000 |
| 23 | Train-balanced | 15 | 6 / 4 / 2 | 0.66667 | 0.75000 | 0.57143 | 0.36364 |
| 41 | Unweighted | 20 | 0 / 0 / 8 | 0 | 0.21741 | 0.50000 | 0 |
| 41 | Train-balanced | 20 | 6 / 8 / 2 | 0.54545 | 0.83333 | 0 | 0.40000 |

The line metric includes eligible lines on **all** cases, including negative
configurations. Weighted reference-only line false alerts are 2/2/4, on two/two/
four of eight negative views; full line false positives are 4/4/8. Every weighted
arm recovers four Cisco positives and two of four JunOS positives. This is
reused synthetic selection, not proved cross-vendor generalization or acceptable
false-alert volume. All outcomes are retained; no best seed/checkpoint is promoted.

Common **unweighted** selection line BCE changes 0.18160→0.12053,
0.16551→0.16834 and 0.18658→0.11333 for the three pairs. It does not improve in
every seed. Full traces preserve pre-update train and post-update validation
losses; saved-checkpoint diagnostics measure both after the selected update.
The coefficient increases zero-logit line loss scale by 1120/592 ≈ 1.89189,
so this intervention does not isolate class cost from shared-task optimization
or clipping. Anomaly/category tradeoffs prevent an all-tasks improvement claim.

The same single-record sigmoid scores feed every ranking/vendor slice without
slice-shaped sigmoid recomputation; BCE uses full-batch logits to reproduce
the saved objective. AP and trapezoidal PR-AUC are recorded separately. Paired
network-cluster uncertainty enumerates all four ordered resamples of the **two**
authored selection networks and retains every delta plus descriptive 95-percentile
intervals. These intervals condition on fitted/selected checkpoints, exclude
retraining/selection uncertainty and do not constitute significance, physical
independence, representative coverage or an independent quality interval.

All six save/load prediction comparisons passed. The seed-17 default report,
weights and model identity exactly reproduce the previous bilateral checkpoint;
97 retained historical/source files remain byte-identical. The installed runtime
has 231 byte-equal source files. Independent review, lint, default/Linux/win32
type checks, 133 source-focused checks, 283 installed checks, 283 Pydantic 2.14
parent checks and 2832 full passes/27 skips support this implementation slice.
New local live-engine/PostgreSQL/browser runs were not performed. Independent
real-confirmed quality, corpus scale, calibration and the full MVP gate remain
open; the weighted format is not activated.

## Controlled localization task rescaling

The follow-up [installed experiment](evaluation/owned-localization-task-rescaling.json)
changes only the existing localization task coefficient `w3`, keeping the
train-balanced positive/negative cost ratio 17.5. It adds three predetermined
fits (seeds 17/23/41, 20 updates) and retains all six preceding controls without
retraining or overwriting them. Nine outcomes, including failures to improve,
are available on the same complete authored truth table.

Before fitting, eligible TRAIN counts determine
`w3 = (positive + negative) / (negative + positive * class_ratio) = 592/1120`.
Effective negative/positive row weights become 0.5285714286/9.25, still in ratio
17.5, with total train mass 592. This normalizes mean train row weight and
zero-logit loss, **not** gradient norm, clipping frequency, AdamW trajectory or
epoch-selection effects. Those mechanisms were not separately measured. The
factor is fixed for validation too; selection prevalence does not recalculate it.

```powershell
python -m ml.training.fixture_transfer_smoke --source-model private/fixture-encoder --source-sha256 <full-pin> --manifest private/fixture-manifest.json --records private/fixture-records.json --owned-scenario bilateral-telnet-0.1.0 --seed 17 --epochs 20 --line-objective train-balanced --localization-task-weight 0.5285714285714286 --output artifacts/new-task-rescaled-transfer
```

The CLI uses existing `LossWeights` validation before reading source files or
creating output. No new training format, loss reduction or evaluator is added.
Default/explicit `1.0` keep the previous protocol and model identity; severity
and the other four task coefficients stay unchanged in the measured runs.
Train-balanced with zero task weight refuses, not silent untrained localization.

| Seed | Selected epoch | Line TP / FP / FN | Line F1 | Line AP | Anomaly F1 | Category F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 17 | 20 | 6 / 4 / 2 | 0.66667 | 0.77500 | 0.54545 | 0.54545 |
| 23 | 15 | 6 / 4 / 2 | 0.66667 | 0.75000 | 0.50000 | 0.36364 |
| 41 | 20 | 6 / 12 / 2 | 0.46154 | 0.83333 | 0 | 0.40000 |

The [preceding table](#train-balanced-bilateral-line-objective) retains the six
unweighted/unit-task-weight controls. Relative to train-balanced `w3=1`, scaling
improves the first seed's anomaly/category F1, worsens the second seed's anomaly
F1 and increases the third seed's false lines from 8 to 12. Negative-reference
line alerts are 2/2/6 on two/two/six of eight negative views. Common unweighted
line BCE is 0.14302/0.17837/0.14679: worse than each unit-task-weight balanced
control. The intervention is therefore **not** a general repair, a selected
winning coefficient or proof of why the models fail. Default training and online
selection remain unchanged; all three 0.4 models stay offline.

All five first pre-update loss components exactly match each same-seed balanced
control, including localization; only the total is reweighted. Subsequent
components/weights/checkpoints can differ. Each run selects the first minimum
of its own validation total; these differently scaled totals are not a quality
comparison. Common unweighted BCE, exact single-record AP/trapezoidal PR-AUC,
strict 0.5 line decisions and anomaly/category outcomes are recorded separately.
The public comparison labels explicitly identify the scaled candidate and either
the balanced or unweighted reference; an inherited private diagnostic key was
renamed in the projection without changing any numbers or original evidence.

Six predeclared pair comparisons enumerate all four ordered network-cluster
resamples, with descriptive percentile endpoints. Only two hypothetical
selection networks contribute. These conditional intervals exclude retraining
and model-selection uncertainty and do not establish significance, physical
independence or representative quality. Formatting views do not become new data.
Reserved-test features/labels, calibration/threshold fitting and activation
remain unused.

All three actual save/load prediction checks passed, six historical identities
and 173 historical files remain unchanged. The new installed package has 231
byte-equal runtime source files; actual diagnostics checked 55 target-only imports,
installed regressions 110. Checks: 91 focused plus 32 final-module cases,
293 installed and 293 Pydantic 2.14 parent cases, 2842 full passes/27 skips;
ruff/mypy default/Linux/win32 pass. No new local live-engine/PostgreSQL/browser
run was performed. This is a functional §13B/14 optimization experiment, not
independent real quality, corpus-scale completion, calibration or the full MVP.
