# Synthetic line localization

`synthetic-lines-0.1.0` learns to identify added/replaced lines in the current
configuration. This is a frozen-encoder baseline trained on synthetic changes,
not evidence that a line is faulty or a production anomaly detector.

## Targets and coordinates

The existing mutation pipeline generates examples after network/site/device
splitting. Current and original text are compared with deterministic line-level
`SequenceMatcher(autojunk=False)`. Inserted and replaced current-file lines are
positive; reference configurations contain no injected-change positives. Line
numbers are one-based, and every prediction carries the current text SHA-256.
LF versus CRLF alone does not create positive labels.

Pure deletions have no corresponding current-file line. The mutation engine's
`affected_lines` can contain a nearby anchor, which is useful for displaying a
diff but is **not** a valid positive training target. Deletion-only examples
are excluded from this localization objective and counted in the report. For
mixed changes, both surviving neighbors of a deletion gap are ignored unless
they are themselves inserted/replaced lines. Detecting absent commands remains
a configuration-level task; this model cannot point to a nonexistent line.

These targets describe edited text, not semantic causality. Identical repeated
lines can have multiple valid diff alignments, and unchanged lines may still
contain pre-existing anomalies. Single-mutation examples and the original
split/template limitations from [classification](mutation-classification.md)
still apply.

## Features and training

The frozen MLM encoder produces contextual token vectors. Source-line alignment
is retained across blocks and token windows. Every ordinary token contributes
to its source lines; for multi-line tokens the weight is shared equally.
Weighted means produce one vector per physical line. Padding and special tokens
never contribute. A line with no aligned tokens has no prediction (`null`), not
a zero score; such lines are excluded from training. Missing alignment on a
positive target is an error.

A linear sigmoid head is trained with weighted binary cross entropy. The
positive weight is negative/positive line count from **train only**, and that
same weight is used in validation loss. Both partitions must contain positive
and negative lines. The lowest validation-loss epoch is restored. The fixed
decision rule is score > 0.5; thresholds are not tuned here. Scores are
uncalibrated, particularly because training reweights positive labels.

Limits cover examples, encoded windows and physical lines, independently per
partition. Limits fail the job instead of silently truncating. Training runs
offline on CPU with a fixed seed and restored RNG/thread/determinism state.
Encoder weights, caller model state, tokenizer and test text remain untouched.
Inference requires only the current sanitized record, not its original text,
diff, parent identity or mutation labels.

## Metrics and smoke command

Install the [MLM training dependencies](mlm-training.md), then:

```powershell
python -m ml.training.localization_smoke --output artifacts/line-localizer-v1
```

The demonstration uses synthetic Telnet/AAA changes and runs 20 head-training
epochs. In the initial local run, train contains 111 lines with 12 positive
targets; validation contains 21 lines with just 2 positives. Changed-line
precision is 0.4, recall 1.0, F1 0.5714, average precision 0.7: both changed
lines are found, with three false positives. This is a pipeline smoke check on
variants of one validation device, not a reliable estimate of real-world
quality. No threshold/model tuning should be based on these tiny figures.

Reports include per-class line precision/recall/F1 and average precision,
support counts, class weight, epoch losses, corpus fingerprints, skipped
mutations, deletion-only exclusions and the encoder hash. Validation selects
the model and therefore is not an independent test. No real or held-out test
evaluation, severity prediction or risk-fusion integration is performed.

## Persistence and use

`save_localizer` creates a new local directory with the existing encoder
checkpoint plus `localizer.json` and its checksum. `load_localizer` checks file
inventory/limits, integrity, encoder binding, report consistency, tensor shape
and finite weights. Partial bundles are rejected. Only load trusted storage;
checksums do not authenticate the producer. Artifacts stay outside Git.

```python
from ml.training.localization import load_localizer, predict_lines

result = load_localizer(checkpoint_directory)
line_scores = predict_lines(result, sanitized_record)
```
