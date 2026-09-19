# Train-reference context experiment

This optional experiment tests additional unchanged-reference contexts at a
fixed decision threshold. It is not a collection of new independent networks.
Augmentation is **off by default** and the measured candidate is not adopted.

## Construction and isolation

`management-comments-0.1.0` prepends three deterministic comment contexts to
each original training reference. Comments mention SSH, Telnet and AAA, using
`!` for Cisco and `#` for JunOS. Command text remains byte-for-byte intact.
Variants retain source, record, device/network IDs and the original parent hash,
with a new content hash. No injected mutation does not imply certified health.

Augmentation happens after split validation and pretrained-corpus checks, on
train references only. No validation/test variants are used for training.
Generated hashes are checked against held-out hashes. Expanded examples, lines
and windows are budgeted. Reports retain the original training fingerprint,
an effective augmented fingerprint, and a separate added-reference count.
Original references remain the source of mutation diff targets: added comments
cannot change positive labels through a replaced parent lookup.

## Paired comparison

Both runs use the same frozen encoder/tokenizer, seed, 20-epoch budget,
optimizer, learning rate, validation set and threshold 0.5. Class weighting is
fixed from the original training lines before adding references. The report's
`weight_reference_lines` and `weight_reference_positive_lines` record those
counts; legacy checkpoints without them use their original train counts.
Best-epoch selection still uses validation: this is development diagnostics,
not an independent test.

```powershell
python -m ml.training.reference_experiment --encoder artifacts/line-localizer-stable-v1/encoder --output artifacts/reference-context-fixed-weight-v1
```

The new output directory contains both localizers, their diagnostic reports and
`comparison.json`. An `.incomplete` marker remains if interrupted. Previous
artifacts and default behavior are unchanged. The CLI uses the existing synthetic
fixtures and does not download new sources.

For an explicit API experiment, set
`LinePolicy(reference_augmentation="management-comments-0.1.0", feature_version="stable-lines-0.1.0")`.

## Measured result: candidate rejected

Six training reference configurations produce 18 additional context variants.
Scored training lines increase from 111 to 255, with 12 positive lines unchanged.
These variants are **not 18 additional independent devices**.

On the three original validation configurations from one device:

| Run | Correctly found changed lines | False positives | Missed changed lines |
|---|---:|---:|---:|
| Baseline | 2 | 3 | 0 |
| Augmented, fixed original class weight | 0 | 0 | 2 |

Across the four paired formatting variants the counts are 8/12/0 versus 0/0/8.
The candidate suppresses detections instead of improving separation, so it is
not suitable for promotion.

An earlier exploratory run recomputed class weighting after augmentation and
produced 2/4/0 on original validation, also worse than baseline. That result
motivated freezing the weight. This is not a pre-registered comparison; both
local runs were retained and neither provides independent test evidence.

More rows alone do not establish improvement. Next useful data work requires
genuinely different lab/reference configurations with provenance and reviewed
labels, not additional comment copies or tuning on this validation device.
