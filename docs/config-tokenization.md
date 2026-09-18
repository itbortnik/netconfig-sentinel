# Configuration blocks and BPE

`config-blocks-0.1.0` partitions an imported sanitized configuration into
contiguous source slices. Each block carries its category, source identity,
source and text SHA-256, deterministic block ID, and inclusive line range.
Concatenating the blocks reproduces the original text, including comments,
whitespace, line endings, and unsupported commands.

Categories cover management, interfaces, VLAN/L2, ACL/prefix-list/route-map,
BGP, OSPF, and static routes. Unknown regions remain `unknown`. A JunOS line
containing several categories is retained as `mixed`. These labels describe
structure, not proof that every command is semantically supported.

Cisco segmentation follows top-level commands and indented stanzas. JunOS
supports both `set` and hierarchical syntax; a lexical brace stack respects
quoted strings and multiline comments and rejects unfinished structures.
Blocks can be fragments of a larger JunOS stanza and retain their original
line ranges; they are model inputs, not independently executable configs.

## Training and persistence

`train_config_tokenizer` accepts an audited `DatasetSplitResult`, validates its
assignments and entity boundaries, then uses only deduplicated train records.
Training order is sorted by source and record ID. Validation/test text never
enters vocabulary learning. The upstream deduplication and split stages remain
responsible for near-duplicate isolation.

`config-bpe-0.1.0` uses local byte-level BPE from Tokenizers 0.23.2. The full byte
alphabet supports unseen Unicode and preserves source text. There is no
normalization or case folding. The default vocabulary target is 8,192 tokens,
with a maximum of 16,384; smaller settings support smoke tests. The actual
vocabulary size is recorded and can be below the target on small corpora.

Special IDs are fixed: PAD=0, UNK=1, CLS=2, SEP=3, MASK=4. Literal special-token
strings in configuration text are encoded as content bytes. No configurations
are sent to a remote service and no pretrained weights are downloaded.

The JSON bundle stores the complete tokenizer, checksum, policy, library and
segmentation versions, train counts, and a training-input fingerprint. Saving
refuses overwrite. Loading is size-bounded and verifies checksum, versions,
vocabulary size, special IDs, and byte-level processing settings. Keep generated
bundles in the ignored `artifacts/` directory. Checksums detect content changes;
they do not authenticate the publisher.

## Encoding and provenance

`encode_block` emits consecutive windows, including every content token once.
The context length defaults to 512 and can be configured up to 1,024. Each
window reserves two positions for CLS/SEP and pads the final window. Oversized
commands can span windows. No tail is silently discarded.

Each content token carries the source line or lines covered by its character
offsets. Special tokens and padding have no source lines. Attention and special
token masks distinguish model input from padding and generated framing.

```python
from pathlib import Path

from ml.preprocessing.blocks import segment_configuration
from ml.preprocessing.tokenization import (
    encode_block, load_tokenizer, save_tokenizer, train_config_tokenizer,
)

artifact = train_config_tokenizer(split_result)
save_tokenizer(artifact, Path("artifacts/tokenizer-v1.json"))
restored = load_tokenizer(Path("artifacts/tokenizer-v1.json"))
windows = [
    window
    for block in segment_configuration(sanitized_record)
    for window in encode_block(block, restored)
]
```

This stage prepares model inputs. Self-supervised objectives, encoder training,
and detection metrics are subsequent stages. Fixture-based tokenizer tests do
not establish anomaly-detection performance or production corpus readiness.

Implementation references: [BPE trainer](https://huggingface.co/docs/tokenizers/api/trainers),
[byte-level pre-tokenizer](https://huggingface.co/docs/tokenizers/en/api/pre-tokenizers),
and [encoding offsets](https://huggingface.co/docs/tokenizers/en/api/encoding).
