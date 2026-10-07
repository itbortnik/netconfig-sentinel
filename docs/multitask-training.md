# Joint supervised configuration heads

`ml.training.multitask` provides five outputs over source-aligned frozen encoder
features: binary anomaly logits, multi-label category logits, current-file line
logits, five declared severity logits and a learned similar-case embedding.
A residual low-rank feature adapter and small attention pooler combine block
embeddings. This is **not** LoRA inside transformer attention, full encoder
fine-tuning, a pretrained general-purpose model download or an activated API
detector. The HTTP analysis workflow does not yet consume these weights.

## Architecture and objective

Each supported structural block is encoded in disjoint, source-aligned tokenizer
windows. Content token vectors are averaged within the block and within every
source line they overlap. Special/padding tokens do not enter the means. All
windows are included or the configured budget fails; no silent file truncation.
Unencoded source lines have no manufactured vector and remain unscored.
Role, vendor, device, site and network IDs are not model input features.

The same trainable residual feature adapter feeds block attention and line
features. Block attention is normalized within each configuration and produces
one configuration representation. Permuting blocks permutes attention weights
without changing the pooled predictions; attention is an aggregation diagnostic,
not causal evidence, a line explanation or a topology proof. Anomaly/category
scores use independent sigmoid heads; severity uses five softmax classes
`info/low/medium/high/critical`. The projection normalizes nonzero embedding
vectors for a cosine similar-case objective.

The configurable objective is:

```text
L = w1*L_anomaly + w2*L_category + w3*L_localization
  + w4*L_severity + w5*L_contrastive
```

Binary tasks use BCE-with-logits on explicitly annotated targets, severity uses
cross entropy and embeddings use pairwise cosine embedding loss with recorded
margin. Similarity groups are explicit reviewed labels, not automatic claims
that configurations from the same vendor/site are equivalent. The metric term
requires both positive and negative pairs. Its pair-count supervision is recorded
separately from configuration count; each pair participates once.

Weights must be finite, nonnegative and not all zero. `-100` targets mean unknown
and are excluded, never treated as normal, low severity or negative category.
Every enabled task must have usable train and validation supervision. To disable
a missing task, explicitly record weight zero; inference then returns `null` for
that task instead of random untrained-head scores. Unknown category targets are
supported in training but the complete-annotation metric adapter refuses them.

The PyTorch primitives are documented in [BCE-with-logits](https://docs.pytorch.org/docs/stable/generated/torch.nn.BCEWithLogitsLoss.html),
[cross entropy](https://docs.pytorch.org/docs/stable/generated/torch.nn.CrossEntropyLoss.html)
and [cosine embedding loss](https://docs.pytorch.org/docs/stable/generated/torch.nn.CosineEmbeddingLoss.html).

## Annotation and isolation contract

`SupervisedExample` contains a sanitized `ImportedDatasetRecord`, its original
parent hash and a `SupervisedAnnotation`. The annotation binds the exact source
hash, annotation/source-review hashes, origin, target semantics, anomaly/category
targets, optional severity, reviewed localization and optional similarity group.
Operators must retain the reviewed artifacts referred to by these hashes.
Integrity metadata does not attest authorization or semantic ground truth.

Derived examples retain their original source/record identity, entity group,
capture time, vendor and role. The audited dataset split chooses their partition;
the caller cannot relabel a test parent as training. Entity/source leakage is
checked again. Test labels never enter training or epoch selection. Identical
derived configurations cannot be duplicated or cross partitions. The annotation
catalog, source hash and line anchors must match every example. Positive
category/severity/line labels require an explicit positive anomaly label.

The encoder and tokenizer must match the original train/validation fingerprints
of the supplied split. This prevents accidentally using a checkpoint selected on
a different validation corpus while describing this run as isolated. It also
means the legacy format accepts the project's trusted MLM checkpoints, **not**
arbitrary third-party pretrained encoders. The separately versioned
[joint Stage A -> B path](pretraining-transfer.md) now also accepts the project's
six-objective checkpoints with regenerated exposure and retained semantic labels.
External foundation transfer with compatible tokenizer is still required.
The compact synthetic smoke is not evidence for training from scratch at scale.

`injected_mutation` and `confirmed_anomaly` semantics cannot be mixed in one
training objective. A real-confirmed source cannot use injected-mutation truth.
The unmodified synthetic reference only means no operation was injected; it does
not establish device health. Actual annotated severity is never inferred from a
mutation recipe, policy severity or detector score. Deletion-only changes retain
the positive configuration label but provide no positive current-file line;
they are excluded from line training and counted separately during evaluation.

## Reproducibility and bounds

`train_multitask()` deep-copies and freezes the encoder, extracts features under
`no_grad`, and trains only the residual feature adapter, pooler and heads using
CPU AdamW, gradient clipping and a fixed seed. Temporary random/thread/
deterministic settings are restored, including on failure. It selects the epoch
with lowest recorded weighted validation objective, not test scores.

The current trainer uses an explicit bounded full batch: default at most 64
examples per partition, configurable up to 256, with total window/feature-value
budgets and per-configuration block/line limits. This is a reproducible local
training path, not a claim that the target large corpus has been trained or a
distributed/streaming trainer. Budget overruns fail without dropping examples.

Reports bind encoder/tokenizer, train/validation examples **including annotation
content**, all policies/weights, origins, usable target counts, parameter counts,
each component/total loss and selected epoch. The frozen encoder hash is checked
before/after training. Components must agree with the weighted totals. Test
evaluation and production quality remain false.

```python
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_training import train_multitask

result = train_multitask(
    split_result, trusted_encoder, annotated_examples,
    head_policy=HeadPolicy(classes=("routing", "management")),
    loss_weights=LossWeights(),
)
```

Only use all default task weights when the corresponding reviewed targets exist.
Similar-case embeddings, scores and attention remain confidential model outputs;
they do not change online risk, findings, severity, patch approval or verification.
Returned scores are uncalibrated until a separately fitted calibration is applied
outside this trainer. Validity of a neural output does not establish network
reachability or safety.

## Local bundle and demonstration

`save_multitask()` creates a new bundle with a hash-checked encoder subdirectory,
`heads.json` containing report/weights, and `heads.sha256`. A writing marker makes
incomplete output recognizable. Loading rejects changed inventory, symlinks,
oversized files, checksum mismatch, invalid reports, incompatible tensor shapes,
nonfinite weights or mismatched encoder/tokenizer/parameter counts. Files must
come from trusted storage; hashes do not authenticate a publisher. Existing
bundles are never overwritten. Optimizer resume is not included.

```powershell
python -m ml.training.multitask_smoke --output artifacts/multitask-smoke-v1
python -m ml.evaluation.multitask_validation --model artifacts/multitask-smoke-v1 --output artifacts/multitask-validation-v1
```

The authored fixture has Telnet/AAA recipes and an unmodified reference. Each
example also has a leading-blank view with shifted line annotations. These are
paired formatting views, not new independent devices, networks or confirmed
anomalies. Similarity groups refer to recipe labels, not proved cross-vendor
semantic equivalence. Severity has no reviewed labels and is explicitly disabled.
All-five-term unit tests use declared synthetic severity solely to exercise the
loss contract, not to report real severity accuracy.

The measured [training report](evaluation/multitask-training.json) and
[validation report](evaluation/multitask-validation.json) were produced locally
on 2026-10-06. The run has 36 train/6 validation views, just one independent
validation device, 8,986 trainable parameters and 133,560 total parameters.
It does **not** meet the recommended 25–50 million-parameter corpus-trained
architecture. Category macro-F1 remains **0** at the fixed threshold; the line
head makes no false positive on these six views but misses half the positive
lines. This is not an independent-test improvement or baseline-superiority claim.
Missing JunOS/real cohorts, unknown-anomaly labels, severity supervision and
calibration remain explicit. See [offline evaluation](offline-evaluation.md).
