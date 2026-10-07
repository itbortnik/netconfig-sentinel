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
