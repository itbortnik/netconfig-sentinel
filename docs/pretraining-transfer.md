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
