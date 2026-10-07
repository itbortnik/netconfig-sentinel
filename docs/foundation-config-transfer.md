# External frozen encoder → configuration heads

This optional offline path trains configuration-specific heads on hidden token
features of one reviewed, pinned external checkpoint. It does **not** call the
document-vector index, sentence similarity encoder output, instruct provider,
HTTP detector or a network device. The same publisher weights can serve two
different pipelines; their identities, pooling and claims remain separate.

## Reviewed source and adaptation

The supported source is `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`,
revision `e8f8c211226b894fcb81acc59f3b34ba3efd5f42`. Its
[publisher model card](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2)
declares Apache-2.0 and describes sentence/paragraph representations. That is a
reviewed license **declaration**, not an independent audit of its training-data
rights, complete training corpus or network-configuration suitability.
`external_training_exposure=unknown`, `configuration_pretrained=false` and
`external_pretraining_isolation_proven=false` remain mandatory report fields.
Local split checks cannot prove isolation from the external pretraining corpus.

The existing fixed inventory/checksum loader verifies all ten publisher files
before constructing native `BertModel` and strictly loading safetensors. It
does not load pickle/custom code or download anything. The known positional
buffer compatibility rule is unchanged. Optional dependencies are those of
`.[retrieval]`; installing that extra does not fetch a model. Follow the
[explicit acquisition procedure](document-vector-retrieval.md) to obtain the
reviewed source, or supply its already verified local directory.

All 117,653,760 source parameters stay frozen, with every nested module in
evaluation mode and no gradients. A CPU tensor digest, actual tokenizer state,
publisher-file manifest, source dimensions and dependency versions bind the
trained result. A residual low-rank **feature** adapter, learned block-attention
pooler and anomaly/category/localization/severity/embedding heads are trained.
This is parameter-efficient adaptation outside the encoder, **not attention
LoRA**, full-encoder fine-tuning or the recommended smaller from-scratch model.

## Exact source alignment and training gates

Only sanitized configuration content enters the encoder. Vendor/role/site/device
metadata are never appended to features. Lossless semantic segmentation retains
unknowns and comments. The fixed external tokenizer is not retrained on local
train/validation/test records. Truncation/padding are disabled; disjoint windows
cover **all** content tokens, each with at most 126 tokens plus framing tokens.
Token character offsets map back to physical lines, including Unicode/CRLF.
Content-token means form block and line matrices; framing tokens do not
contribute. Blank-only blocks/lines have no invented content score. Whitespace
spans do not create localization anchors on blank lines. No full-network
context, causal evidence or vendor syntax validity is inferred from attention.

Original audited split parents, current-text hashes and explicit annotations are
required. Entity/content leakage, test parents, mismatched metadata, missing
reviewed targets and duplicate derived inputs fail. Local test records never
become features for fitting or epoch selection. Unknown labels are ignored,
not negative; deletion-only localization never invents a current line. Severity
requires explicit labels, not policy severity. A zero objective weight disables
its output instead of exposing an untrained score. Bounded examples/windows/
feature values fail without silent truncation. Shared numerical losses and
validation selection match the existing native trainer; RNG, deterministic
settings and thread count are restored on success and failure.

## Private checkpoint and inference

`save_foundation_transfer()` exclusively creates a new directory containing
`heads.json` and `heads.sha256`; `.incomplete` denotes an unfinished write.
The large external weights are **not copied** into that checkpoint, and their
local path is not serialized. Loading requires both an explicit `source_root`
and an independently retained **full model identity**, not just the adjacent
file checksum. Exact inventory, bounded reads, duplicate JSON keys, linked
parents/files, tensor shapes/counts/finiteness and source/runtime bindings are
checked. The pin is checked before decoding head tensors or allocating the
external model. Never load an unreviewed checkpoint merely because it has a hash.

`predict_foundation_transfer()` recomputes the frozen-source binding and returns
source-aligned uncalibrated numeric outputs; disabled heads are null and
unscored lines remain null. Mutable weights/tokenizer/nested train mode/gradients
fail instead of silently changing the model. These checks are integrity gates,
not publisher authentication or a defense against privileged concurrent Python
mutation/OS TOCTOU. Model artifacts/features remain private and need OS access
control; they are not encrypted API storage. No optimizer resume or general
arbitrary-model ingestion is implemented.

## Measured owned demonstration

```powershell
python -m pip install -e ".[dev,retrieval]"
python -m ml.training.foundation_smoke --source-model artifacts/multilingual-minilm-e8f8c211 --output artifacts/foundation-config-v1
```

Choose an existing parent and unused output plus unused sibling report paths.
The command always uses the owned 24-config/12-hypothetical-network fixture,
not arbitrary customer files. It verifies original source weights, trains,
saves/reloads with the full pin and checks exact prediction equality. The
following generated reports are selection diagnostics on 2026-10-07:
[training](evaluation/foundation-config-training.json),
[validation](evaluation/foundation-config-validation.json).

There were 48 train/12 validation views, four validation devices and 20 epochs;
114,521 parameters trained out of 117,768,281 total. Selected epoch 20 reduced
weighted validation loss from 2.02194 to 1.28966. Severity was disabled. At fixed
0.5 thresholds anomaly/category F1 and line recall are **0**, with no positive
prediction. Anomaly average precision 0.83333 and category average precision 1
on these few authored cases are **not** independent quality or justification
for tuning thresholds on selection data. Cisco positives are absent from this
validation fixture; positive injections are JunOS-only. Blank formatting views
are not independent networks or new real labels.

The measured parsing/inference latency includes binding checks and is CPU/local,
not a production benchmark or target-hardware SLA. No real-confirmed cohort,
independent test, unknown-anomaly evaluation, fitted calibration, baseline
superiority or cross-vendor generalization is proven. Native pre/post patch
diagnostics currently select native project bundles only; this experimental
external checkpoint is not silently substituted there or in HTTP risk fusion.
See [readiness](readiness.md) for remaining acceptance gates.
