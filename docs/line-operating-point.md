# Training-reference operating points

`line-operating-point-0.1.0` is an optional decision artifact for a fixed line
localizer. It changes only the decision threshold, not scores, embeddings,
weights or the model's default threshold of 0.5. It is experimental and always
records `deployment_ready: false` and `calibrated_probability: false`.

## Selection and boundaries

The fitter scores only original **train** configurations. It verifies their
fingerprint against the encoder training corpus and revalidates split entity
boundaries. Validation/test text is neither parsed nor scored during fitting.
The encoder itself was previously selected with validation loss; this procedure
does not turn the overall pipeline into an independent validation experiment.

For N scored reference lines and requested alert rate r, the allowed count is
floor(r*N). Choose the lowest threshold at least 0.5 for which no more than that
many reference scores are strictly greater than the threshold. Ties are handled
together. The default rate is zero: threshold equals max(0.5, max train-reference
score). Null/unscorable lines are excluded and counted. Bounds on records and
total lines prevent unbounded fitting; prediction's window budget is per record.

This is an empirical alert budget, not a false-positive-rate guarantee. Original
configurations are not certified healthy; suppressing their alerts can suppress
real anomalies. Training scores are optimistic, and different networks may
behave differently. No probability calibration, risk classification, formal
safety guarantee or production threshold approval is performed.

## Persist and explicitly opt in

```powershell
python -m ml.training.line_threshold --model artifacts/line-localizer-stable-v1 --output artifacts/line-operating-point-v1.json
python -m ml.training.localization_evaluation --model artifacts/line-localizer-stable-v1 --operating-point artifacts/line-operating-point-v1.json --output artifacts/line-diagnostics-threshold-v1.json
```

The CLI uses the synthetic fixture corpus. For another audited corpus, call
`fit_line_operating_point(result, splits)` directly. Artifacts bind the training
fingerprint to exact encoder/head weights, tokenizer and preprocessing mode.
Checksums catch accidental corruption; only load trusted files. Existing files
are never overwritten. A mismatched model rejects the threshold.

`predict_with_operating_point(result, record, point)` applies the threshold
explicitly and preserves source hashes, line numbers, raw scores and nulls.
Ordinary `predict_lines` and diagnostics without `--operating-point` retain the
model's original 0.5 rule. Diagnostic reports include the complete operating
point so their decision policy is auditable.

## Measured experiment: not suitable for activation

On the stable-input synthetic smoke model, the zero-reference-alert threshold
is **0.6855882406234741**, fitted on 36 lines from six training configurations.
Training reference alerts drop from nine to zero.

On the same paired validation diagnostics used previously:

| Decision rule | True-positive lines | False-positive lines | False-negative lines |
|---|---:|---:|---:|
| Original threshold 0.5 | 8 | 12 | 0 |
| Training-reference threshold | 0 | 0 | 8 |

The eight positive occurrences are variants of only two changed lines from one
validation device. Removing all alerts also removes all correct detections.
This is **not** a quality improvement and the threshold is **not enabled by
default**. The result exposes insufficient separation for this strict operating
point. Broader training examples and independent evaluation are needed before
choosing an operational precision/recall tradeoff; these development diagnostics
must not be advertised as unseen test results.
