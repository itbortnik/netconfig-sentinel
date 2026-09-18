"""Bounded CPU masked-language-model training for configuration windows."""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from typing import Literal, cast

import torch
from pydantic import BaseModel, ConfigDict, Field, model_validator
from torch import Tensor, nn

from ml.datasets import DatasetSplit, DatasetSplitResult
from ml.preprocessing.blocks import digest, segment_configuration
from ml.preprocessing.tokenization import (
    TokenizerArtifact,
    TokenWindow,
    _validate_split_entities,
    encode_block,
)
from ml.training.masking import IGNORE_LABEL, MASKING_VERSION, MaskedWindow, mask_window


class EncoderPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    hidden_size: int = Field(default=64, ge=16, le=512)
    layers: int = Field(default=2, ge=1, le=8)
    heads: int = Field(default=4, ge=1, le=8)
    feedforward_size: int = Field(default=128, ge=16, le=2048)
    dropout: float = Field(default=0.1, ge=0, lt=1)

    @model_validator(mode="after")
    def compatible_heads(self) -> EncoderPolicy:
        if self.hidden_size % self.heads:
            raise ValueError("hidden size must be divisible by attention heads")
        return self


class TrainingPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    seed: int = Field(default=17, ge=0, le=2**31 - 1)
    epochs: int = Field(default=2, ge=1, le=100)
    batch_size: int = Field(default=8, ge=1, le=64)
    learning_rate: float = Field(default=0.001, gt=0, le=0.1)
    weight_decay: float = Field(default=0.01, ge=0, le=1)
    mask_probability: float = Field(default=0.15, gt=0, le=1)
    gradient_clip: float = Field(default=1, gt=0, le=100)
    max_windows: int = Field(default=10000, ge=1, le=100000)


class EpochMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    epoch: int = Field(ge=1)
    train_loss: float = Field(ge=0)
    validation_loss: float = Field(ge=0)
    train_masked_tokens: int = Field(ge=1)
    validation_masked_tokens: int = Field(ge=1)


class TrainingReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["config-mlm-0.1.0"] = "config-mlm-0.1.0"
    masking_version: str = MASKING_VERSION
    torch_version: str
    encoder_policy: EncoderPolicy
    training_policy: TrainingPolicy
    tokenizer_sha256: str
    training_fingerprint: str
    validation_fingerprint: str
    train_windows: int = Field(ge=1)
    validation_windows: int = Field(ge=1)
    parameter_count: int = Field(ge=1)
    best_epoch: int = Field(ge=1)
    metrics: tuple[EpochMetrics, ...]
    test_evaluated: Literal[False] = False

    @model_validator(mode="after")
    def validate_epochs(self) -> TrainingReport:
        if tuple(item.epoch for item in self.metrics) != tuple(
            range(1, self.training_policy.epochs + 1)
        ):
            raise ValueError("report must contain every completed epoch in order")
        best = min(self.metrics, key=lambda item: item.validation_loss).epoch
        if self.best_epoch != best:
            raise ValueError("best epoch must match lowest validation loss")
        if self.masking_version != MASKING_VERSION:
            raise ValueError("unsupported masking version")
        return self


class ConfigEncoderMLM(nn.Module):
    """Bidirectional encoder with token/position embeddings and an MLM head."""

    def __init__(self, vocab_size: int, context_length: int, policy: EncoderPolicy) -> None:
        super().__init__()
        self.tokens = nn.Embedding(vocab_size, policy.hidden_size, padding_idx=0)
        self.positions = nn.Embedding(context_length, policy.hidden_size)
        # Construct each layer independently so initialization is not cloned.
        self.layers = nn.ModuleList(
            [
                nn.TransformerEncoderLayer(
                    d_model=policy.hidden_size,
                    nhead=policy.heads,
                    dim_feedforward=policy.feedforward_size,
                    dropout=policy.dropout,
                    activation="gelu",
                    batch_first=True,
                )
                for _ in range(policy.layers)
            ]
        )
        self.norm = nn.LayerNorm(policy.hidden_size)
        self.head = nn.Linear(policy.hidden_size, vocab_size)

    def forward(self, input_ids: Tensor, attention_mask: Tensor) -> Tensor:
        return cast(Tensor, self.head(self.encode(input_ids, attention_mask)))

    def encode(self, input_ids: Tensor, attention_mask: Tensor) -> Tensor:
        """Return contextual token embeddings before the reconstruction head."""
        positions = torch.arange(input_ids.shape[1], device=input_ids.device)
        hidden = self.tokens(input_ids) + self.positions(positions)
        for layer in self.layers:
            hidden = layer(hidden, src_key_padding_mask=~attention_mask.bool())
        return cast(Tensor, self.norm(hidden))


@dataclass
class TrainingResult:
    model: ConfigEncoderMLM
    tokenizer: TokenizerArtifact
    report: TrainingReport


def train_masked_language_model(
    splits: DatasetSplitResult,
    tokenizer: TokenizerArtifact,
    *,
    encoder_policy: EncoderPolicy | None = None,
    training_policy: TrainingPolicy | None = None,
) -> TrainingResult:
    """Train on train, select best epoch on validation, leave test untouched."""
    encoder = encoder_policy or EncoderPolicy()
    policy = training_policy or TrainingPolicy()
    tokenizer = TokenizerArtifact.model_validate(tokenizer.model_dump())
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    _validate_split_entities(splits)
    partitions = {partition.split: partition for partition in splits.partitions}
    fingerprints = {}
    windows: dict[DatasetSplit, list[TokenWindow]] = {}
    for split in (DatasetSplit.TRAIN, DatasetSplit.VALIDATION):
        records = sorted(
            partitions[split].records, key=lambda item: (item.source_id, item.record_id)
        )
        fingerprints[split] = digest(
            json.dumps(
                [(item.source_id, item.record_id, item.sanitized_sha256) for item in records],
                separators=(",", ":"),
            )
        )
        if split is DatasetSplit.TRAIN and fingerprints[split] != tokenizer.training_fingerprint:
            raise ValueError("tokenizer was trained on a different training corpus")
        windows[split] = []
        for record in records:
            for block in segment_configuration(record):
                windows[split].extend(encode_block(block, tokenizer))
                if len(windows[split]) > policy.max_windows:
                    raise ValueError("training window budget exceeded; no silent truncation")
    previous_threads = torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    warn_only = torch.is_deterministic_algorithms_warn_only_enabled()
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(policy.seed)
            model = ConfigEncoderMLM(
                tokenizer.actual_vocab_size,
                tokenizer.policy.context_length,
                encoder,
            )
            optimizer = torch.optim.AdamW(
                model.parameters(),
                lr=policy.learning_rate,
                weight_decay=policy.weight_decay,
            )
            validation = _masked(windows[DatasetSplit.VALIDATION], tokenizer, policy, epoch=0)
            metrics: list[EpochMetrics] = []
            best_loss = math.inf
            best_epoch = 0
            best_weights: dict[str, Tensor] = {}
            for epoch in range(1, policy.epochs + 1):
                train = _masked(windows[DatasetSplit.TRAIN], tokenizer, policy, epoch=epoch)
                random.Random(policy.seed + epoch).shuffle(train)
                model.train()
                train_loss, train_tokens = _run_batches(model, train, policy, optimizer)
                model.eval()
                with torch.no_grad():
                    val_loss, val_tokens = _run_batches(model, validation, policy)
                metrics.append(
                    EpochMetrics(
                        epoch=epoch,
                        train_loss=train_loss,
                        validation_loss=val_loss,
                        train_masked_tokens=train_tokens,
                        validation_masked_tokens=val_tokens,
                    )
                )
                if val_loss < best_loss:
                    best_loss, best_epoch = val_loss, epoch
                    best_weights = {
                        key: value.detach().clone() for key, value in model.state_dict().items()
                    }
            model.load_state_dict(best_weights)
            model.eval()
    finally:
        torch.use_deterministic_algorithms(deterministic, warn_only=warn_only)
        torch.set_num_threads(previous_threads)
    report = TrainingReport(
        torch_version=torch.__version__,
        encoder_policy=encoder,
        training_policy=policy,
        tokenizer_sha256=tokenizer.tokenizer_sha256,
        training_fingerprint=fingerprints[DatasetSplit.TRAIN],
        validation_fingerprint=fingerprints[DatasetSplit.VALIDATION],
        train_windows=len(windows[DatasetSplit.TRAIN]),
        validation_windows=len(windows[DatasetSplit.VALIDATION]),
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        best_epoch=best_epoch,
        metrics=tuple(metrics),
    )
    return TrainingResult(model, tokenizer, report)


def _masked(
    windows: list[TokenWindow],
    tokenizer: TokenizerArtifact,
    policy: TrainingPolicy,
    *,
    epoch: int,
) -> list[MaskedWindow]:
    return [
        mask_window(
            window,
            vocab_size=tokenizer.actual_vocab_size,
            seed=policy.seed,
            epoch=epoch,
            probability=policy.mask_probability,
        )
        for window in windows
    ]


def _run_batches(
    model: ConfigEncoderMLM,
    windows: list[MaskedWindow],
    policy: TrainingPolicy,
    optimizer: torch.optim.Optimizer | None = None,
) -> tuple[float, int]:
    total_loss, total_tokens = 0.0, 0
    for offset in range(0, len(windows), policy.batch_size):
        batch = windows[offset : offset + policy.batch_size]
        ids = torch.tensor([item.input_ids for item in batch], dtype=torch.long)
        attention = torch.tensor([item.attention_mask for item in batch], dtype=torch.bool)
        labels = torch.tensor([item.labels for item in batch], dtype=torch.long)
        count = int((labels != IGNORE_LABEL).sum().item())
        logits = model(ids, attention)
        loss = (
            nn.functional.cross_entropy(
                logits.reshape(-1, logits.shape[-1]),
                labels.reshape(-1),
                ignore_index=IGNORE_LABEL,
                reduction="sum",
            )
            / count
        )
        if not torch.isfinite(loss):
            raise ValueError("non-finite MLM loss")
        if optimizer is not None:
            optimizer.zero_grad(set_to_none=True)
            loss.backward()  # type: ignore[no-untyped-call]
            nn.utils.clip_grad_norm_(
                model.parameters(), policy.gradient_clip, error_if_nonfinite=True
            )
            optimizer.step()
        total_loss += float(loss.detach().item()) * count
        total_tokens += count
    if not total_tokens:
        raise ValueError("no masked tokens to train or evaluate")
    return total_loss / total_tokens, total_tokens
