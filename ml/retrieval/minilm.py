"""Pinned, tensor-only multilingual document encoder with no network or custom code."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from types import MappingProxyType
from typing import cast

import numpy as np
import torch
from app.explanation.vector_index import EmbeddingIdentity, RetrievalUnavailable, validate_text
from numpy.typing import NDArray
from safetensors.torch import load_file
from tokenizers import Tokenizer
from torch import Tensor
from transformers import BertConfig, BertModel

MODEL_ID = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
REVISION = "e8f8c211226b894fcb81acc59f3b34ba3efd5f42"
PIPELINE_VERSION = "minilm-all-content-window128-mean-l2-0.1.0"
FILES = MappingProxyType(
    {
        "config.json": (645, "6300193cb75e01cf80c96decef7187dfb33094d97cc1490b7ead6ff134476e4e"),
        "config_sentence_transformers.json": (
            122,
            "b8c64b5cece00d8424b4896ea75b512b6008576088497609dfeb6bd63e6d36b8",
        ),
        "model.safetensors": (
            470641600,
            "eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b",
        ),
        "modules.json": (229, "8f4b264b80206c830bebbdcae377e137925650a433b689343a63bdc9b3145460"),
        "README.md": (3888, "1e98ea05b0de579fcaad3d625b62ea55647142ed674d5f5ebf1440e4bbbb6f23"),
        "sentence_bert_config.json": (
            53,
            "70f4448f31320443fe3557cacea5abf2dcc4915dda8c80646bec9f3bb0aa5a1f",
        ),
        "special_tokens_map.json": (
            239,
            "378eb3bf733eb16e65792d7e3fda5b8a4631387ca04d2015199c4d4f22ae554d",
        ),
        "tokenizer_config.json": (
            526,
            "5036ea374ffedd706e3bef33e2e0d6953cb868ef8a490e76e32ba0faa37a6b9b",
        ),
        "tokenizer.json": (
            9081518,
            "2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8",
        ),
        "1_Pooling/config.json": (
            190,
            "4be450dde3b0273bb9787637cfbd28fe04a7ba6ab9d36ac48e92b11e350ffc23",
        ),
    }
)
MAX_TEXTS = 256
MAX_WINDOWS = 1024
CONTENT_WINDOW = 126
BATCH_SIZE = 8


def verify_model_files(root: Path) -> None:
    """Integrity of this pinned publisher artifact, not a claim about training data."""
    try:
        for directory, expected in (
            (root, {name for name in FILES if "/" not in name} | {"1_Pooling"}),
            (root / "1_Pooling", {"config.json"}),
        ):
            if (
                any(
                    item.is_symlink() or item.is_junction()
                    for item in (directory, *directory.parents)
                )
                or not directory.is_dir()
                or {item.name for item in directory.iterdir()} != expected
            ):
                raise ValueError("unsupported model inventory")
        for name, (size, expected_sha) in FILES.items():
            path = root / name
            if path.is_symlink() or path.is_junction() or not path.is_file():
                raise ValueError("unsupported model file")
            with path.open("rb") as source:
                if source.seek(0, 2) != size:
                    raise ValueError("unexpected model file size")
                source.seek(0)
                if hashlib.file_digest(source, "sha256").hexdigest() != expected_sha:
                    raise ValueError("model checksum mismatch")
    except (OSError, ValueError):
        raise RetrievalUnavailable("Document encoder is unavailable.") from None


def _windows(tokenizer: Tokenizer, texts: tuple[str, ...]) -> tuple[list[list[int]], list[int]]:
    if not 1 <= len(texts) <= MAX_TEXTS:
        raise RetrievalUnavailable("Document encoder is unavailable.")
    windows: list[list[int]] = []
    owners: list[int] = []
    for owner, text in enumerate(texts):
        validate_text(text)
        # Source literals such as <mask> are ordinary text, not user-supplied control tokens.
        ids = tokenizer.encode(text, add_special_tokens=False).ids
        if not ids:
            raise RetrievalUnavailable("Document encoder is unavailable.")
        for start in range(0, len(ids), CONTENT_WINDOW):
            windows.append([0, *ids[start : start + CONTENT_WINDOW], 2])
            owners.append(owner)
            if len(windows) > MAX_WINDOWS:
                raise RetrievalUnavailable("Document encoder is unavailable.")
    return windows, owners


def _load_model(root: Path) -> BertModel:
    configuration = BertConfig.from_dict(json.loads((root / "config.json").read_bytes()))
    # This exact config is hash-pinned before allocation: 12 layers, 384 hidden, 250037 vocab.
    with torch.random.fork_rng(devices=[]):
        model = cast(Callable[[BertConfig], BertModel], BertModel)(configuration)
    state = load_file(root / "model.safetensors", device="cpu")
    # The 2021 checkpoint persists this deterministic buffer; current BERT does not.
    # Validate only that one compatibility item; all learned tensors load strictly.
    positions = state.pop("embeddings.position_ids", None)
    if (
        positions is None
        or positions.dtype != torch.int64
        or not torch.equal(positions, torch.arange(512).unsqueeze(0))
    ):
        raise RetrievalUnavailable("Document encoder is unavailable.")
    if any(not torch.isfinite(tensor).all().item() for tensor in state.values()):
        raise RetrievalUnavailable("Document encoder is unavailable.")
    model.load_state_dict(state, strict=True)
    # The upstream subclass narrows these inherited methods to untyped signatures.
    torch.nn.Module.train(model, False)
    torch.nn.Module.requires_grad_(model, False)
    return model


class LocalDocumentEncoder:
    """CPU-only reviewed checkpoint. No AutoModel, remote code, pickle or auto-download."""

    def __init__(self, root: Path) -> None:
        verify_model_files(root)
        try:
            self._model = _load_model(root)
            self._tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
            self._tokenizer.no_truncation()
            self._tokenizer.no_padding()
            self._tokenizer.encode_special_tokens = True
            if [self._tokenizer.token_to_id(name) for name in ("<s>", "</s>", "<pad>")] != [
                0,
                2,
                1,
            ]:
                raise ValueError("unsupported tokenizer control mapping")
            file_digest = hashlib.sha256(
                json.dumps(dict(FILES), sort_keys=True, separators=(",", ":")).encode("ascii")
            ).hexdigest()
            self._identity = EmbeddingIdentity(
                model_id=MODEL_ID,
                revision=REVISION,
                files_sha256=file_digest,
                pipeline_version=PIPELINE_VERSION,
                dimensions=384,
                runtime_versions=tuple(
                    f"{name}={version(name)}"
                    for name in ("torch", "transformers", "tokenizers", "safetensors", "numpy")
                ),
            )
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            raise RetrievalUnavailable("Document encoder is unavailable.") from None

    @property
    def identity(self) -> EmbeddingIdentity:
        return self._identity

    def encode(self, texts: tuple[str, ...]) -> NDArray[np.float32]:
        windows, owners = _windows(self._tokenizer, texts)
        # Window weights are their full attention length. Each original content token is
        # represented once; CLS/SEP occur per window. This is not silent 128-token truncation.
        totals = torch.zeros(len(texts), 384, dtype=torch.float32)
        counts = torch.zeros(len(texts), 1, dtype=torch.float32)
        try:
            with torch.inference_mode():
                for start in range(0, len(windows), BATCH_SIZE):
                    batch = windows[start : start + BATCH_SIZE]
                    width = max(len(ids) for ids in batch)
                    ids = torch.tensor([row + [1] * (width - len(row)) for row in batch])
                    attention = torch.tensor(
                        [[1] * len(row) + [0] * (width - len(row)) for row in batch]
                    )
                    hidden = cast(
                        Tensor, self._model(ids, attention_mask=attention).last_hidden_state
                    )
                    if hidden.shape != (len(batch), width, 384) or not torch.isfinite(hidden).all():
                        raise RetrievalUnavailable("Document encoder is unavailable.")
                    sums = (hidden * attention.unsqueeze(-1)).sum(dim=1)
                    for position, row in enumerate(batch):
                        owner = owners[start + position]
                        totals[owner] += sums[position]
                        counts[owner] += len(row)
                vectors = totals / counts
                norms = torch.linalg.vector_norm(vectors, dim=1, keepdim=True)
                if not torch.isfinite(vectors).all() or torch.any(norms <= 1e-12):
                    raise RetrievalUnavailable("Document encoder is unavailable.")
                return np.asarray((vectors / norms).numpy(), dtype=np.float32)
        except (RuntimeError, ValueError):
            raise RetrievalUnavailable("Document encoder is unavailable.") from None
