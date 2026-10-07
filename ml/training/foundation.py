"""Reviewed external weights used as a frozen, source-aligned configuration encoder.

This is not document-vector lookup: hidden content tokens are pooled into exact
configuration blocks/physical lines before training task-specific feature heads.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_right
from pathlib import Path
from typing import Literal, cast

import torch
from pydantic import BaseModel, ConfigDict, Field
from tokenizers import Tokenizer
from torch import Tensor, nn

from ml.datasets import ImportedDatasetRecord
from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.blocks import digest, segment_configuration
from ml.retrieval import minilm
from ml.training.multitask_training import AlignedFeatures

PIPELINE_VERSION = "config-foundation-content128-block-line-0.1.0"


def frozen_state_digest(model: nn.Module) -> str:
    """Bounded-memory CPU tensor digest; never convert a foundation vocabulary to JSON."""
    if any(module.training for module in model.modules()) or any(
        parameter.requires_grad or parameter.grad is not None for parameter in model.parameters()
    ):
        raise ValueError("configuration foundation must be fully frozen in evaluation mode")
    hasher = hashlib.sha256()
    for name, tensor in sorted(model.state_dict().items()):
        if tensor.device.type != "cpu" or tensor.dtype not in (torch.float32, torch.int64):
            raise ValueError("configuration foundation requires supported CPU tensor types")
        if not bool(torch.isfinite(tensor).all()):
            raise ValueError("configuration foundation contains nonfinite tensors")
        hasher.update(
            json.dumps(
                (name, str(tensor.dtype), list(tensor.shape)), separators=(",", ":")
            ).encode()
        )
        hasher.update(memoryview(tensor.detach().contiguous().numpy()).cast("B"))
    return hasher.hexdigest()


class FoundationIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    model_id: Literal["sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"] = (
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    )
    revision: Literal["e8f8c211226b894fcb81acc59f3b34ba3efd5f42"] = (
        "e8f8c211226b894fcb81acc59f3b34ba3efd5f42"
    )
    publisher_license_declaration: Literal["Apache-2.0"] = "Apache-2.0"
    license_declaration_reviewed: Literal[True] = True
    external_training_exposure: Literal["unknown"] = "unknown"
    configuration_pretrained: Literal[False] = False
    files_sha256: Digest
    weights_sha256: Digest
    tokenizer_sha256: Digest
    pipeline_version: Literal["config-foundation-content128-block-line-0.1.0"] = (
        "config-foundation-content128-block-line-0.1.0"
    )
    hidden_size: Literal[384] = 384
    content_window: Literal[126] = 126
    parameter_count: int = Field(ge=1, le=200000000, strict=True)
    runtime_versions: tuple[str, ...]


class ConfigFoundation:
    """Fixed local safetensors/BERT loader; no download, custom code, pickle or network."""

    def __init__(self, root: Path) -> None:
        threads = torch.get_num_threads()
        try:
            torch.set_num_threads(1)
            self._initialize(root)
        finally:
            torch.set_num_threads(threads)

    def _initialize(self, root: Path) -> None:
        minilm.verify_model_files(root)
        self._model = minilm._load_model(root)
        self._tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        self._tokenizer.encode_special_tokens = True
        if [self._tokenizer.token_to_id(name) for name in ("<s>", "</s>", "<pad>")] != [0, 2, 1]:
            raise ValueError("configuration foundation tokenizer controls differ")
        from importlib.metadata import version

        self.identity = FoundationIdentity(
            files_sha256=canonical_hash(dict(minilm.FILES)),
            weights_sha256=frozen_state_digest(self._model),
            tokenizer_sha256=digest(self._tokenizer.to_str()),
            parameter_count=sum(parameter.numel() for parameter in self._model.parameters()),
            runtime_versions=tuple(
                f"{name}={version(name)}"
                for name in ("torch", "transformers", "tokenizers", "safetensors", "numpy")
            ),
        )

    def verify(self) -> FoundationIdentity:
        threads = torch.get_num_threads()
        try:
            torch.set_num_threads(1)
            return self._verify()
        finally:
            torch.set_num_threads(threads)

    def _verify(self) -> FoundationIdentity:
        identity = FoundationIdentity.model_validate(self.identity.model_dump())
        if (
            frozen_state_digest(self._model) != identity.weights_sha256
            or digest(self._tokenizer.to_str()) != identity.tokenizer_sha256
            or sum(parameter.numel() for parameter in self._model.parameters())
            != identity.parameter_count
            or identity.files_sha256 != canonical_hash(dict(minilm.FILES))
        ):
            raise ValueError("configuration foundation weights/tokenizer/identity binding differs")
        return identity

    def features(
        self,
        record: ImportedDatasetRecord,
        *,
        max_windows: int,
        max_feature_values: int = 4000000,
    ) -> AlignedFeatures:
        """Disjoint full-content windows; no silent truncation or metadata-derived features."""
        threads = torch.get_num_threads()
        try:
            torch.set_num_threads(1)
            return self._features(
                record, max_windows=max_windows, max_feature_values=max_feature_values
            )
        finally:
            torch.set_num_threads(threads)

    def _features(
        self,
        record: ImportedDatasetRecord,
        *,
        max_windows: int,
        max_feature_values: int,
    ) -> AlignedFeatures:
        self.verify()
        record = ImportedDatasetRecord.model_validate(record.model_dump())
        blocks = segment_configuration(record)
        total_lines = len(record.sanitized_text.splitlines())
        size = self.identity.hidden_size
        if (
            type(max_windows) is not int
            or not 1 <= max_windows <= 100000
            or (
                type(max_feature_values) is not int
                or not 1024 <= max_feature_values <= 16000000
                or (total_lines + len(blocks)) * size > max_feature_values
            )
        ):
            raise ValueError("configuration foundation feature/window budget exceeded")
        line_sums = torch.zeros(total_lines, size)
        line_counts = torch.zeros(total_lines)
        block_features: list[Tensor] = []
        count = 0
        with torch.no_grad():
            for block in blocks:
                encoded = self._tokenizer.encode(block.text, add_special_tokens=False)
                if not encoded.ids:
                    if block.text.strip():
                        raise ValueError("nonempty source block has no foundation tokens")
                    continue  # Blank-only blocks have no invented content embedding.
                starts = [0]
                physical_lines = block.text.splitlines(keepends=True)
                for line in physical_lines:
                    starts.append(starts[-1] + len(line))
                anchors = []
                for start, end in encoded.offsets:
                    if not 0 <= start < end <= len(block.text):
                        raise ValueError("foundation token has invalid source character offsets")
                    first = min(len(physical_lines) - 1, bisect_right(starts, start) - 1)
                    last = min(len(physical_lines) - 1, bisect_right(starts, end - 1) - 1)
                    anchors.append(
                        tuple(
                            block.start_line + index
                            for index in range(first, last + 1)
                            if block.text[
                                max(start, starts[index]) : min(end, starts[index + 1])
                            ].strip()
                        )
                    )
                windows = (len(encoded.ids) + 125) // 126
                count += windows
                if count > max_windows:
                    raise ValueError("configuration foundation window budget exceeded")
                block_sum = torch.zeros(size)
                for start in range(0, len(encoded.ids), 126):
                    content = encoded.ids[start : start + 126]
                    ids = torch.tensor([[0, *content, 2]])
                    hidden = cast(
                        Tensor,
                        self._model(ids, attention_mask=torch.ones_like(ids)).last_hidden_state,
                    )
                    if hidden.shape != (1, len(content) + 2, size) or (
                        not bool(torch.isfinite(hidden).all())
                    ):
                        raise ValueError("configuration foundation hidden states differ")
                    vectors = hidden[0, 1:-1]
                    block_sum += vectors.sum(dim=0)
                    for index, vector in enumerate(vectors):
                        for number in anchors[start + index]:
                            line_sums[number - 1] += vector
                            line_counts[number - 1] += 1
                block_features.append(block_sum / len(encoded.ids))
        if not block_features:
            raise ValueError("configuration source has no foundation content")
        selected = line_counts > 0
        return AlignedFeatures(
            blocks=torch.stack(block_features),
            lines=line_sums[selected] / line_counts[selected, None],
            line_numbers=tuple(int(index) + 1 for index in torch.where(selected)[0]),
            total_lines=total_lines,
            windows=count,
        )
