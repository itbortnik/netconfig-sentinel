# Localization robustness diagnostics

The `line-diagnostics-0.1.0` evaluator inspects a fixed localizer on its known
validation partition. It does not train weights, tune thresholds or evaluate
test configurations. The train/validation fingerprints must match the saved
localizer. Mutations inherit the original split boundaries and collision checks.

For each validation reference and single-mutation example, the evaluator uses:

- the original text;
- two leading blank lines;
- one vendor-style comment before the configuration;
- CRLF line endings.

The same transformation is applied to parent and child before computing targets.
Thus formatting changes do not become positive labels. They test model
sensitivity, not new independent data. All variants of a device still count as
one unique device. This is not a multi-vendor benchmark when the selected
validation partition contains only one vendor.

## Run

After the [localizer smoke run](line-localization.md):

```powershell
python -m ml.training.localization_evaluation --model artifacts/line-localizer-v1 --output artifacts/line-diagnostics-v1.json
```

Output must be a new file. The command uses the same tiny synthetic fixture
corpus as the smoke trainer. For a different audited corpus, call
`evaluate_localization(result, splits)` directly. The CLI does not import a new
dataset or broaden source permissions.

## Report interpretation

The JSON report includes aggregate confusion counts, precision/recall/F1,
false-positive lines per evaluated configuration, unchanged-reference alert
counts, and breakdowns by vendor, mutation type and formatting variant.
Per-case records retain source hash and line numbers for true positives,
false positives and false negatives, without copying configuration text.
Line numbers refer to the transformed current file; compare its recorded hash
before using them. The report binds encoder, tokenizer and exact head weights.

Deletion-only examples remain excluded, ambiguous deletion-gap neighbors are
ignored, and unscorable lines are counted. Positive targets without a score
fail evaluation. No-positive/undefined precision/recall/F1 uses zero. Example
and total physical-line budgets bound the expanded diagnostic run; the existing
window budget applies per predicted configuration.

These false positives mean disagreement with synthetic edit labels, not a
verified false security alert. Reference configs are not certified healthy.
The denominator is evaluated configurations, including variants, **not**
independent devices. Variant metrics must not be pooled and presented as a
larger held-out test set.

## Initial measured result

The existing 20-epoch smoke localizer was evaluated without modifying weights:

| Variant | True-positive lines | False-positive lines | False-negative lines |
|---|---:|---:|---:|
| Original | 2 | 3 | 0 |
| Leading blank lines | 2 | 9 | 0 |
| Comment context | 2 | 3 | 0 |
| CRLF | 2 | 4 | 0 |

There are 12 evaluated configurations but only **one independent device**.
All four unchanged-reference variants trigger an alert. Leading blank lines
account for six additional false-positive lines; CRLF changes one additional
decision. The model is therefore sensitive to harmless formatting and is not
ready for production alerts. The original two changed-line targets are found
in every variant, but this tiny fixture cannot establish generalization.

Next work should address formatting robustness and unchanged-reference errors
using training-only examples, then compare a frozen model on broader independent
data. These diagnostic variants must not be relabeled as an untouched test set
after influencing development decisions.

## Stable-input comparison

The `stable-lines-0.1.0` preprocessing mode was trained with the same fixture,
seed and epoch count, then measured on the identical diagnostic cases:

| Variant | Previous false-positive lines | Stable-input false-positive lines |
|---|---:|---:|
| Original | 3 | 3 |
| Leading blank lines | 9 | 3 |
| Comment context | 3 | 3 |
| CRLF | 4 | 3 |

Changed targets remain detected in all variants. Six inserted blank lines now
have null scores because they are explicitly outside the normalized model input;
they are counted as unscorable, not correct negative predictions. The extra CRLF
error disappears. Remaining command-level errors are unchanged: every reference
variant still triggers an alert. This fixes the tested formatting sensitivity,
not general anomaly quality, and uses no independent test evidence.

Use new artifact paths to preserve the previous baseline:

```powershell
python -m ml.training.localization_smoke --output artifacts/line-localizer-stable-v1
python -m ml.training.localization_evaluation --model artifacts/line-localizer-stable-v1 --output artifacts/line-diagnostics-stable-v1.json
```
