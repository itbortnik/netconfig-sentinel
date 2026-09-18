"""Local byte-level BPE training, integrity metadata, and lossless windows."""

from __future__ import annotations

import json
from bisect import bisect_right
from importlib.metadata import version
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from tokenizers import Tokenizer, decoders, models, pre_tokenizers, trainers

from ml.datasets.splitting import DatasetSplit, DatasetSplitResult
from ml.preprocessing.blocks import (
    ConfigurationBlock,
    digest,
    segment_configuration,
)

TOKENIZER_VERSION = "config-bpe-0.1.0"
SPECIAL_TOKENS = ("[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]")


class TokenizerPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    vocab_size: int = Field(default=8192, ge=261, le=16384)
    min_frequency: int = Field(default=2, ge=1)
    context_length: int = Field(default=512, ge=8, le=1024)


class TokenizerArtifact(BaseModel):
    """One serializable, hash-checked tokenizer and its training provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    tokenizer_version: Literal["config-bpe-0.1.0"] = "config-bpe-0.1.0"
    segmentation_version: Literal["config-blocks-0.1.0"] = "config-blocks-0.1.0"
    library_version: str
    policy: TokenizerPolicy
    training_split: Literal["train"] = "train"
    training_record_count: int = Field(ge=1)
    training_block_count: int = Field(ge=1)
    training_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    actual_vocab_size: int = Field(ge=261)
    tokenizer_json: str
    tokenizer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_tokenizer(self) -> TokenizerArtifact:
        if digest(self.tokenizer_json) != self.tokenizer_sha256:
            raise ValueError("tokenizer checksum mismatch")
        tokenizer = Tokenizer.from_str(self.tokenizer_json)
        if tokenizer.get_vocab_size() != self.actual_vocab_size:
            raise ValueError("tokenizer vocabulary size mismatch")
        if self.actual_vocab_size > self.policy.vocab_size:
            raise ValueError("vocabulary exceeds policy target")
        if any(tokenizer.token_to_id(token) != index for index, token in enumerate(SPECIAL_TOKENS)):
            raise ValueError("special token IDs do not match the versioned contract")
        specification = json.loads(self.tokenizer_json)
        if specification["model"]["type"] != "BPE":
            raise ValueError("expected a BPE tokenizer")
        if specification.get("truncation") or specification.get("padding"):
            raise ValueError("tokenizer must not truncate or pad input internally")
        if specification.get("normalizer") or specification.get("post_processor"):
            raise ValueError("tokenizer must preserve source text without extra processing")
        if (
            specification.get("pre_tokenizer")
            != {
                "type": "ByteLevel",
                "add_prefix_space": False,
                "trim_offsets": True,
                "use_regex": True,
            }
            or specification.get("decoder", {}).get("type") != "ByteLevel"
        ):
            raise ValueError("tokenizer must use the versioned byte-level pipeline")
        if specification["model"].get("dropout") is not None:
            raise ValueError("inference must be deterministic")
        return self


class TokenWindow(BaseModel):
    """Bounded model input with original source lines for every content token."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    block_id: str
    tokenizer_sha256: str
    window_index: int = Field(ge=0)
    content_token_start: int = Field(ge=0)
    content_token_end: int = Field(ge=1)
    input_ids: tuple[int, ...]
    attention_mask: tuple[int, ...]
    special_tokens_mask: tuple[int, ...]
    source_lines: tuple[tuple[int, ...], ...]

    @model_validator(mode="after")
    def validate_alignment(self) -> TokenWindow:
        length = len(self.input_ids)
        if not all(
            len(values) == length
            for values in (
                self.attention_mask,
                self.special_tokens_mask,
                self.source_lines,
            )
        ):
            raise ValueError("token window arrays must have matching lengths")
        if self.content_token_end <= self.content_token_start:
            raise ValueError("invalid content token interval")
        return self


def train_config_tokenizer(
    splits: DatasetSplitResult,
    *,
    policy: TokenizerPolicy | None = None,
) -> TokenizerArtifact:
    """Use only deduplicated train representatives from an audited split result."""
    effective = policy or TokenizerPolicy()
    # Revalidate even if the caller used model_copy to modify an existing result.
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    _validate_split_entities(splits)
    partition = next(item for item in splits.partitions if item.split is DatasetSplit.TRAIN)
    records = sorted(partition.records, key=lambda item: (item.source_id, item.record_id))
    blocks = [block for record in records for block in segment_configuration(record)]
    tokenizer = Tokenizer(models.BPE(unk_token="[UNK]"))
    tokenizer.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tokenizer.decoder = decoders.ByteLevel()
    trainer = trainers.BpeTrainer(  # type: ignore[no-untyped-call]
        vocab_size=effective.vocab_size,
        min_frequency=effective.min_frequency,
        special_tokens=list(SPECIAL_TOKENS),
        show_progress=False,
        initial_alphabet=sorted(pre_tokenizers.ByteLevel.alphabet()),
    )
    tokenizer.train_from_iterator((block.text for block in blocks), trainer=trainer)
    serialized = tokenizer.to_str()
    fingerprint = digest(
        json.dumps(
            [(record.source_id, record.record_id, record.sanitized_sha256) for record in records],
            separators=(",", ":"),
        )
    )
    return TokenizerArtifact(
        library_version=version("tokenizers"),
        policy=effective,
        training_record_count=len(records),
        training_block_count=len(blocks),
        training_fingerprint=fingerprint,
        actual_vocab_size=tokenizer.get_vocab_size(),
        tokenizer_json=serialized,
        tokenizer_sha256=digest(serialized),
    )


def encode_block(block: ConfigurationBlock, artifact: TokenizerArtifact) -> tuple[TokenWindow, ...]:
    """Cover all content tokens in disjoint windows, each framed by CLS/SEP."""
    block = ConfigurationBlock.model_validate(block.model_dump())
    artifact = TokenizerArtifact.model_validate(artifact.model_dump())
    tokenizer = Tokenizer.from_str(artifact.tokenizer_json)
    # Literal control-token strings in source must remain ordinary source bytes.
    tokenizer.encode_special_tokens = True
    encoding = tokenizer.encode(block.text, add_special_tokens=False)
    line_starts = [0]
    for line in block.text.splitlines(keepends=True):
        line_starts.append(line_starts[-1] + len(line))
    token_lines = []
    for start, end in encoding.offsets:
        first = min(block.end_line, block.start_line + bisect_right(line_starts, start) - 1)
        last = min(
            block.end_line, block.start_line + bisect_right(line_starts, max(start, end - 1)) - 1
        )
        token_lines.append(tuple(range(first, last + 1)))
    capacity = artifact.policy.context_length - 2
    windows: list[TokenWindow] = []
    for start in range(0, len(encoding.ids), capacity):
        end = min(start + capacity, len(encoding.ids))
        padding = capacity - (end - start)
        ids = (2, *encoding.ids[start:end], 3, *([0] * padding))
        windows.append(
            TokenWindow(
                block_id=block.block_id,
                tokenizer_sha256=artifact.tokenizer_sha256,
                window_index=len(windows),
                content_token_start=start,
                content_token_end=end,
                input_ids=ids,
                attention_mask=(1,) * (end - start + 2) + (0,) * padding,
                special_tokens_mask=(1,) + (0,) * (end - start) + (1,) * (padding + 1),
                source_lines=((), *token_lines[start:end], (), *([()] * padding)),
            )
        )
    return tuple(windows)


def save_tokenizer(artifact: TokenizerArtifact, path: Path) -> None:
    """Write one local bundle without overwriting an existing artifact."""
    verified = TokenizerArtifact.model_validate(artifact.model_dump())
    with path.open("x", encoding="utf-8", newline="\n") as target:
        target.write(verified.model_dump_json() + "\n")


def load_tokenizer(path: Path) -> TokenizerArtifact:
    """Load a bounded bundle and verify its model checksum and special IDs."""
    if path.is_symlink():
        raise ValueError("tokenizer bundle must not be a symbolic link")
    with path.open("rb") as source:
        content = source.read(16 * 1024 * 1024 + 1)
    if len(content) > 16 * 1024 * 1024:
        raise ValueError("tokenizer bundle exceeds 16 MiB")
    return TokenizerArtifact.model_validate_json(content)


def _validate_split_entities(splits: DatasetSplitResult) -> None:
    placements: dict[tuple[str, str, str], DatasetSplit] = {}
    assignments = {
        (item.record.source_id, item.record.record_id): item for item in splits.assignments
    }
    for assignment in splits.assignments:
        for field in ("network_id", "site_id", "device_id"):
            key = (assignment.record.source_id, field, getattr(assignment, field))
            previous = placements.setdefault(key, assignment.split)
            if previous != assignment.split:
                raise ValueError("entity leakage across tokenizer corpus splits")
    hashes: dict[str, DatasetSplit] = {}
    for partition in splits.partitions:
        for record in partition.records:
            assignment = assignments[(record.source_id, record.record_id)]
            if any(
                getattr(record, field) != getattr(assignment, field)
                for field in (
                    "network_id",
                    "site_id",
                    "device_id",
                    "captured_at",
                )
            ):
                raise ValueError("record metadata differs from its split assignment")
            previous = hashes.setdefault(record.sanitized_sha256, partition.split)
            if previous != partition.split:
                raise ValueError("identical content crosses tokenizer corpus splits")
