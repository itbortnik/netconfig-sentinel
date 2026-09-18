# Masked-token training

`config-mlm-0.1.0` is the first local training slice of Config Transformer.
It trains a bidirectional encoder to reconstruct selected configuration tokens.
Anomaly classification, severity heads, calibration, and real-data evaluation
remain later stages.

## Installation and smoke run

PyTorch is an optional training dependency. For the CPU path tested here:

```powershell
python -m pip install -e ".[dev]"
python -m pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu
New-Item -ItemType Directory -Force artifacts
python -m ml.training.smoke --output artifacts/mlm-smoke-v1
```

Alternatively install `.[dev,training]` for the standard PyTorch distribution.
The demonstration uses nine tiny, explicitly synthetic Cisco/JunOS fixtures,
trains a local vocabulary, runs two epochs, writes a checkpoint, reloads it,
and prints measured losses. Output must be a new directory under an existing
parent. Generated artifacts are ignored by Git.

## Objective and model

Masking version `config-mlm-masking-0.1.0` selects 15% of eligible content
tokens by default, rounded to the nearest count with a minimum of one token
per window. Padding, CLS, SEP, and other reserved IDs are excluded. Of the
selected tokens, 80% are replaced by MASK, 10% by a random ordinary vocabulary
token, and 10% remain unchanged. These are sampling probabilities, not exact
per-batch quotas. Labels at all unselected positions are `-100` and excluded
from cross entropy.

Selection depends on the seed, epoch, block ID, window index, and tokenizer
hash. Training masks change by epoch; validation masks stay fixed so validation
losses are comparable across epochs. Original token windows remain unchanged.

The encoder has token and learned positional embeddings, independently
initialized Transformer layers, layer normalization, and an MLM vocabulary
head. Attention masks prevent attending to padding. The default smoke model
uses two layers, hidden size 64, four heads, and feed-forward size 128. The
configuration also supports larger encoders up to eight layers and hidden
size 512, but no large model is trained automatically.

## Data and reproducibility

The entry point accepts an audited `DatasetSplitResult` and its matching
`TokenizerArtifact`. It revalidates entity boundaries, checks that the
tokenizer's training fingerprint matches train records, and creates windows
for train and validation only. Test content is neither encoded nor evaluated.
The window budget raises an error rather than truncating the corpus silently.

Training uses CPU, one computation thread, a fixed seed, AdamW, gradient
clipping, and deterministic algorithms. Temporary PyTorch RNG, thread-count,
and deterministic settings are restored afterward. Run training as an offline
job; these process-wide settings are not intended for concurrent training in
an API worker. Exact repeatability is tested in one environment; different
hardware or library versions may produce different floating-point results.

Loss is aggregated by the number of selected tokens, not by batch count.
The lowest fixed-mask validation loss selects the returned epoch. Reports
retain both policies, library and masking versions, train/validation input
fingerprints, tokenizer hash, window and parameter counts, and every epoch's
measured loss and masked-token count. Test evaluation is explicitly false.
An MLM loss is not a calibrated anomaly score or an anomaly-detection metric.

## Checkpoints

`save_checkpoint` creates a new directory containing `weights.pt`,
`tokenizer.json`, `report.json`, and a checksum manifest. An `.incomplete`
marker makes interrupted writes recognizable. Existing directories are never
overwritten. `load_checkpoint` checks inventory, file sizes and SHA-256,
verifies tokenizer/report compatibility, then loads a CPU state dictionary
using `weights_only=True` with strict parameter matching and finite-weight
checks. Only load bundles from trusted storage: hashes check integrity, not
publisher identity.

The checkpoint holds the selected model for inference. Optimizer state and
resumable training are not included in this version.

```python
from ml.training.transformer import train_masked_language_model
from ml.training.checkpoint import save_checkpoint

result = train_masked_language_model(split_result, tokenizer_artifact)
save_checkpoint(result, output_directory)
```

Implementation references: [PyTorch encoder layer](https://docs.pytorch.org/docs/stable/generated/torch.nn.TransformerEncoderLayer.html)
and [state dictionary loading](https://docs.pytorch.org/docs/stable/generated/torch.load).
