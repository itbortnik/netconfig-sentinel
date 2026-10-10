# Configuration objective pretraining

`ml.training.pretraining` trains a local configuration encoder jointly on six
explicit objective terms, covering the five pretraining task families. The
older token-only MLM path and checkpoint format remain unchanged. This is an
offline CPU experiment, not a pretrained foundation-model download, production
anomaly detector, calibrated score or completed large-corpus training.

## Targets and their limits

- `token`: existing BERT-style token masking, with 80/10/10 replacement sampling.
- `command`: reconstruct every token overlapping one complete physical command
  within its window. All target tokens become MASK, not partly visible targets.
- `parameter`: reconstruct a validated IP/prefix literal or an explicitly named
  ASN argument (`router bgp`, `remote-as`, `peer-as`, `autonomous-system`). This is
  a conservative lexical typed-literal task, not a complete vendor grammar or
  reconstruction of every possible parameter.
- `replaced_line`: distinguish an original line from a line transplanted from
  another device with the same vendor, structural category and command prefix.
  The donor stays in the parent's original partition. Positive means synthetic
  replacement, **not** an anomaly, malformed command or network failure.
- `same_device`: classify two distinct structural blocks from one device/capture
  versus a block from another same-vendor device, matching the second block's
  category. Identity metadata is not fed into the encoder; source hostnames and
  addresses remain ordinary content and can still be memorized.
- `cross_vendor`: cosine embedding loss on **explicitly labeled** cross-vendor
  configuration pairs within one stated semantic scope. No labels are inferred
  from vendor, site, scenario number, recipe type or parser-confidence score.

Command/parameter targets support Cisco physical commands and JunOS `set`
commands. Hierarchical JunOS commands, descriptions/quoted prose for parameter
targets, and ambiguous inline-comment commands are excluded conservatively.
They still remain in the general token objective. A target spanning windows is
not partly reconstructed while leaving another fragment visible. Token offsets
bind to source characters, including Unicode; literal control-token strings in
configuration text remain ordinary bytes. See [tokenizer offset semantics](https://huggingface.co/docs/tokenizers/main/api/encoding).

Line examples preserve the parent's line position/indentation and record exact
parent/donor hashes and anchors. Only lines wholly represented in one window
with unambiguous line-token features enter this objective. Transplants are not
certified syntax/behavior-preserving edits. Source, device, vendor and template
shortcuts remain evaluation concerns; generator metadata does not prove absence
of artifacts. The original and transplanted views are not independent devices.

`SemanticPair` requires both source hashes, an explicit positive/negative label,
scope, review hash and origin. The referenced review must be retained in trusted
storage. These fields bind declared labels; they do not attest human review,
authorization or functional equivalence. Both sides must be Cisco/JunOS sources
in the **same non-test partition**. Duplicate/reversed/contradictory pairs and
mixed scopes are rejected. Positive and negative targets must exist in both
train and validation for enabled binary/contrastive objectives.

## Training boundary

The tokenizer must match the audited original train fingerprint. Entity/source
split checks run again, duplicate representatives are rejected, and test content
is not encoded. Automatic donors and block pairs cannot cross partitions.
Source records must already have passed the source-review and sanitization
pipeline; this in-memory trainer cannot independently attest those permissions.

The model shares the bidirectional encoder and vocabulary reconstruction head
across token/command/parameter tasks. A line classifier, symmetric block-pair
classifier over absolute difference/product, and normalized configuration
projection implement the remaining tasks. Cross-vendor configuration vectors
pool all content tokens from all their windows; no role/site/device/vendor IDs
are concatenated as features. Padding/special tokens do not enter pooled means.

`PretrainingWeights` controls all six nonnegative finite weights. Cross-vendor
weight defaults to **zero** until reviewed pair labels are supplied. Missing
targets cannot silently disable an enabled task. A disabled component is `null`,
not a measured zero loss; its random task-specific head is not updated or
declared useful. Do not interpret untrained task-specific weights as predictions.

Each epoch accumulates the gradient of the exact weighted mean of each objective
over bounded microbatches and then makes **one** AdamW step. Token objectives
normalize by target-token counts; line/pair objectives normalize by example
counts. This preserves the stated joint weights instead of taking unrelated
optimizer steps per task. Clipping occurs after complete accumulation. Temporary
CPU-thread, random and deterministic settings are restored on success/failure.
Constructed masks/donors/pairs are fixed for this version; the older token-only
trainer's epoch-varying masking remains available separately.

Validation selects the epoch with minimum weighted validation loss. Test is
untouched; all reports keep `test_evaluated` and `production_quality_proven`
false. Reports bind source/derived-objective fingerprints, tokenizer, policies,
weights, source/target counts, semantic scope/origins, parameters and every
component/total loss. A report validates the weighted arithmetic but is not an
attestation that externally supplied labels are true.

Construction bounds records, source windows, objective examples, replacement
candidates and donor-search work. Pair pooling has a separate window budget.
Overruns fail without truncating the corpus. Offline operators must still size
batch/context/model limits for available RAM; these bounds are not a guarantee
that every permitted policy fits every host. This is not a streaming/distributed
trainer for the target large corpus.

## Bundle and runnable demonstration

```python
from ml.training.pretraining import train_configuration_objectives, save_pretraining
from ml.training.pretraining_data import PretrainingWeights

result = train_configuration_objectives(
    split_result, tokenizer_artifact,
    semantic_pairs=reviewed_pairs,
    weights=PretrainingWeights(cross_vendor=0.1),
)
save_pretraining(result, new_output_directory)
```

The new bundle contains tokenizer/report JSON, tensor-only weights and a checksum
manifest. Loading checks complete inventory, no symlinks, bounded files, duplicate
JSON keys, hashes, report/architecture/tokenizer/parameter bindings, strict tensor
shapes and finite values. An incomplete marker and non-overwriting directory
creation protect partial outputs. Checksums identify content, not publishers.
Only load trusted local artifacts. Optimizer resume and conversion into the
legacy MLM-checkpoint format are not included. The separate
[Stage A -> B transfer](pretraining-transfer.md) retains this native objective
bundle and report, instead of relabeling the run as MLM-only training.

```powershell
python -m ml.training.pretraining_smoke --output artifacts/pretraining-objectives-v1 --epochs 10
```

This command authors 24 tiny configurations in 12 paired synthetic networks:
16 train, 4 validation and 4 reserved test configurations. Pair labels only
compare `ipv4_static_route_destinations_and_next_hops`; tests check that exact
route tuple against both parsers. Management defaults, BGP, interfaces, routing
preference and actual reachability are **not** declared equivalent. The fixture
is not a new real dataset or evidence of complete cross-vendor semantics.

The [measured local report](evaluation/configuration-pretraining.json) was
generated on 2026-10-06 with 52,725 parameters and ten epochs. Weighted validation
loss falls from approximately 19.12 to 14.34, mostly from reconstruction terms.
Replacement/block-pair BCE stays near 0.69 and the cross-vendor objective barely
changes: no useful transfer or real anomaly quality is established. No real
confirmed pairs, independent anomaly test, large-corpus result, foundation
pretrained/parameter-efficient transfer or online model activation is claimed.

These objectives use [cross entropy](https://docs.pytorch.org/docs/stable/generated/torch.nn.CrossEntropyLoss.html),
[binary cross entropy with logits](https://docs.pytorch.org/docs/stable/generated/torch.nn.BCEWithLogitsLoss.html)
and [cosine embedding loss](https://docs.pytorch.org/docs/stable/generated/torch.nn.CosineEmbeddingLoss.html).

## Train-only source fixtures

`ml.datasets.fixture_training.prepare_fixture_training_corpus` now connects the
explicit unknown-metadata intake to the **same** byte-BPE, reconstruction target,
CPU objective optimizer and checksum bundle implementations above. It is a
separate `config-fixture-corpus-0.1.0` exposure contract, not a fabricated
`DatasetSplitResult` or a weakened full dataset quality gate.

The source must be approved for training. Its complete raw-hash/vendor inventory,
source ID and acquisition time must match the imported records. Current content
checks and deduplication are repeated; the unknown collection remains indivisible
and entirely train-only. Its inventory includes duplicate members and holds,
while the training fingerprint includes only deduplicated accepted representatives.
Physical network/device/capture/role metadata remain unknown. A hash binds these
declarations, not source rights, true labels or independent topology identity.

Structural segmentation refusals fail by default. An operator must predeclare
`structural_refusals: "exclude"` to hold them, with exact source references/hashes
and an explicit reason in the audit. This option cannot hide content/hash/vendor,
permission, source inventory or size errors. Unknown but segmentable commands
remain in token reconstruction; parser acceptance does not certify vendor syntax.
Token/command/typed-parameter objectives use the existing source-offset logic.
Replaced-line, same-device and cross-vendor tasks are **disabled** and have `null`
losses, not fake supervision from fixture filenames or collection membership.

`train_fixture_tokenizer` trains only on accepted train representatives.
`train_fixture_objectives` uses fixed predeclared epochs and keeps the **final**
epoch, even if an earlier training loss is lower. No validation forward pass,
selection, calibration or test metric is manufactured. The separate
`config-fixture-pretraining-0.1.0` report binds the full exposure audit and protocol;
validation fields are `null`. `save_pretraining` shares the existing writer;
`load_fixture_pretraining` is the explicit loader. The old `load_pretraining` and
ordinary objective-transfer validation refuse this train-only bundle. Optimizer
resume, downstream fixture-aware transfer and registry/online activation are not
implemented by this slice.

The runnable path accepts a private fixture manifest, a JSON list of **all**
sanitized imported records (not merely representatives when duplicates exist),
and an operator-authored protocol JSON:

```powershell
python -m ml.training.fixture_pretraining_cli --manifest private/fixture-manifest.json --records private/imported-fixtures.json --protocol private/protocol.json --output artifacts/new-fixture-run
```

Example protocol for a bounded functional experiment, not production defaults:

```json
{
  "corpus": {"structural_refusals": "exclude", "max_records": 512},
  "tokenizer": {"vocab_size": 512, "min_frequency": 2, "context_length": 64},
  "encoder": {"hidden_size": 32, "layers": 1, "heads": 2, "feedforward_size": 64, "dropout": 0},
  "training": {"seed": 17, "epochs": 2, "batch_size": 16, "embedding_size": 16, "max_records": 512},
  "weights": {"token": 1, "command": 1, "parameter": 1, "replaced_line": 0, "same_device": 0, "cross_vendor": 0}
}
```

The CLI freezes the protocol before BPE/optimization, refuses overwrite, preserves
an incomplete marker on failure, saves the bundle and verifies a load/identity
round trip. Inputs and model artifacts stay in trusted private storage. CLI
failure output does not echo configuration or model exception contents.

[Measured source-fixture training](evaluation/owned-source-fixture-pretraining.json)
on 2026-10-10 uses the already approved pinned Batfish source: 415 complete intake
records, 415 content representatives, three structural holds, 412 train fixtures,
3,445 blocks, 4,569 windows and **142,500 content BPE tokens**. This is distinct
from the earlier 30,819 lexical-token approximation. Padding/special tokens and
multiple epochs do not increase corpus size. The 46,610-parameter encoder trained
for two fixed epochs; train weighted loss changed from 19.0544 to 18.4906.
Validation/test metrics and confirmed real labels remain missing. All configurations,
tokenizer/model artifacts and exposure inventories stay local; only aggregate
evidence is public.

The actual installed wheel retrains this same collection with identical model
identity/weights. It also gives the exact prior report and weights for the existing
six-objective train/validation demonstration and reads a real historical bundle
without rewriting its four files. These are functional/reproducibility checks,
not an independent benchmark or multiple independent corpora. No PoC/MVP scale,
foundation pretraining, anomaly quality or complete Stage A qualification follows
from this small reconstruction run. A downstream transfer must explicitly account
for this source/duplicate/template exposure and unknown device/time identity;
reserved test data must not be recycled to tune it.
