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
