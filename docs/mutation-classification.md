# Synthetic mutation classification

`synthetic-probe-0.1.0` is a small supervised baseline on a frozen MLM encoder.
It predicts an unmodified reference or one injected mutation type. It is not
yet the full Config Transformer detector and does not emit production Findings.

## Label meaning and isolation

`no_injected_mutation` means that the generator did not alter this example.
It does **not** certify that the original configuration is healthy. The other
classes are explicit `MutationType` values, not confirmed real anomalies.
This first classifier handles a single mutation per example, not combinations.

Generation happens after the audited network/site/device split. Each original
and all its derived examples remain in the parent's partition. Only train and
validation are generated and encoded. Test text is not parsed; its recorded
hashes are checked for collisions with derived samples. Exact duplicates across
partitions and contradictory labels for identical text are rejected. This does
not remove all template similarity: template-generalization evaluation is still
required. Unsupported mutations are counted per partition/class; parser
validation errors fail the run. Every requested class must occur in train.

The tokenizer and pretrained encoder must match the original training corpus,
and the pretrained validation fingerprint must match the current validation
partition. Vocabulary is never retrained on mutated or validation examples.

## Model and reports

Content-token embeddings are averaged over all windows of a configuration,
excluding reserved/padding tokens. Long files are not silently truncated.
This token-count-weighted mean is a deliberately simple baseline, not the
planned attention-pooling model. The encoder is copied, frozen and kept in
evaluation mode; only a linear softmax head is trained with full-batch AdamW.
`batch_size` limits encoder feature-extraction batches. Example and window
budgets apply independently to train and validation.

CPU training uses a fixed seed, one thread and deterministic algorithms.
Global RNG/thread/determinism settings are restored, including after errors.
Like MLM training, run this offline, not concurrently inside an API worker.
The epoch with lowest validation cross entropy is restored. Reports include
class order, encoder hash, derived-example fingerprints, counts, skipped
mutations, epoch losses, precision/recall/F1 per class and macro-F1. Average
precision is a step-weighted precision-recall summary, not trapezoidal PR-AUC;
it is null when a class has no positive or no negative validation examples.
Undefined precision/recall/F1 use zero. Macro-F1 includes every requested class.

Validation metrics select the model and are not independent test estimates.
Softmax outputs are uncalibrated; neither the reference probability nor its
complement is a trustworthy production health/risk score. Severity, line
localization, multilabel heads, calibration and real-data evaluation remain
separate later stages.

## Run and persist

Install the CPU dependencies described in [MLM training](mlm-training.md), then:

```powershell
python -m ml.training.classification_smoke --output artifacts/mutation-probe-v1
```

This command creates nine tiny artificial topologies, pretrains a compact MLM,
and runs 20 head-training epochs for Telnet and AAA mutations plus the reference
class. The measured demonstration has 18 train examples and only 3 validation
examples (one original and two variants of one device). Even perfect validation
scores on this fixture do not establish anomaly-detection quality.

`save_probe` writes a new directory containing the existing hash-checked encoder
bundle, `classifier.json` (report and linear weights), and its checksum.
`load_probe` validates the inventory, integrity, encoder binding, head dimensions,
finite weights and report consistency. Existing directories are never overwritten.
Only use trusted local bundles: checksums do not authenticate a publisher.
Generated weights/reports stay under ignored `artifacts/`.

```python
from ml.mutation import MutationType
from ml.training.classification import train_mutation_probe, predict_mutations

result = train_mutation_probe(
    split_result, pretrained_result,
    (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED),
)
probabilities = predict_mutations(result, sanitized_record)
```
