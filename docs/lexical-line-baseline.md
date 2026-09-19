# Lexical line-localization baseline

`lexical-lines-0.1.0` compares the frozen Transformer line head with a simple
character TF-IDF/logistic-regression baseline. It uses the same laboratory
split, parent-derived synthetic AAA/Telnet labels and fixed threshold 0.5.
It is not a calibrated anomaly score, severity estimator or production detector.

## Fixed training procedure

The audited split/mutation pipeline runs before fitting. Vocabulary, IDF and
classifier coefficients are learned from train lines only. The feature policy
is character-within-word n-grams of length 2–5, case preserved, sublinear TF and
at most 10,000 features. Logistic regression uses C=1, balanced class weights,
the liblinear solver, seed 17 and a maximum of 1,000 iterations. Nonconvergence
fails training instead of producing a silently unfinished result.

These settings were chosen before the first comparison and were not searched
against validation scores. There is no pretrained vocabulary, validation-based
epoch selection or threshold fitting for this baseline. Test content is not
parsed or scored; only split metadata/hashes participate in leakage checks.

Insert/replace labels, deletion-gap exclusions and deletion-only omission follow
the existing localizer. Nonempty physical lines are scored independently; empty
lines receive nulls. There is no neighboring-line or network context. CRLF and
leading blank lines preserve the scores of original command lines by construction.
Unknown character fragments have no fitted features; zero-feature vectors use
the learned intercept rather than being classified as definitely safe.

Limits bound training and diagnostic lines and per-record inference size.
Predictions retain the original SHA-256 and one-based source line numbers.
Reports record library version, policies, corpus fingerprints, vocabulary and
fitted-model hashes, line counts and per-case errors. Class balancing means
`predict_proba` values should not be interpreted as calibrated confidence.

## Reproduce the comparison

Use the existing training dependencies and the saved laboratory Transformer:

```powershell
python -m ml.training.lexical_localization --transformer artifacts/laboratory-localizer-v1/model --output artifacts/lexical-laboratory-comparison-v1.json
```

The output path must be new. The comparison requires matching validation
fingerprints, including mutation labels. It stores diagnostics for both models,
not executable pickle files. The lexical model is currently an in-memory
baseline rebuilt by the deterministic training function; no production registry
or service default is changed.

## Initial result

On six original validation configurations from two synthetic devices:

| Model | Correct detections | False positives | Missed changed lines | F1 |
|---|---:|---:|---:|---:|
| Frozen Transformer line head | 4 | 19 | 0 | 0.2963 |
| Character TF-IDF + logistic regression | 4 | 2 | 0 | 0.8 |

Lexical precision is 0.6667 and recall is 1.0. Its counts remain 4/2/0 for each
formatting variant; variants do not count as additional independent devices.
One of the two unchanged references still triggers alerts.

This is an improvement on the **same tiny development fixture**, not proof of
real-world generalization. The labels expose simple lexical differences such
as added Telnet or changed AAA commands, which favors this baseline. It cannot
infer missing commands, peer-AS correctness, reachability, multi-line intent or
unknown network behavior. The result establishes a useful comparison target;
it does not justify discarding contextual models or promoting this baseline to
production. Broader independent data and unseen mutation families are required.
