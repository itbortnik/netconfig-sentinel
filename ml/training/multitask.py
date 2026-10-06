"""Attention-pooled supervised heads and explicit five-term training objective."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, cast

import torch
from pydantic import BaseModel, ConfigDict, Field, model_validator
from torch import Tensor, nn

SEVERITY_CLASSES = ("info", "low", "medium", "high", "critical")
IGNORE_TARGET = -100
Label = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]
Weight = Annotated[float, Field(ge=0, le=100, strict=True)]


class LossWeights(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    anomaly: Weight = 1.0
    category: Weight = 1.0
    localization: Weight = 1.0
    severity: Weight = 1.0
    contrastive: Weight = 0.1

    @model_validator(mode="after")
    def nonzero(self) -> LossWeights:
        if not any(self.model_dump().values()):
            raise ValueError("at least one supervised objective weight must be positive")
        return self


class HeadPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: str = Field(default="multitask-heads-0.1.0", pattern=r"^multitask-heads-0\.1\.0$")
    classes: tuple[Label, ...] = Field(min_length=1, max_length=64)
    embedding_size: int = Field(default=64, ge=2, le=1024, strict=True)
    adapter_rank: int = Field(default=16, ge=1, le=512, strict=True)
    contrastive_margin: float = Field(default=0.2, ge=-1, le=1, strict=True)
    max_examples: int = Field(default=64, ge=2, le=256, strict=True)
    max_blocks_per_configuration: int = Field(default=1024, ge=1, le=4096, strict=True)
    max_lines_per_configuration: int = Field(default=100000, ge=1, le=100000, strict=True)
    max_feature_values: int = Field(default=2000000, ge=1024, le=16000000, strict=True)

    @model_validator(mode="after")
    def unique_classes(self) -> HeadPolicy:
        if len(set(self.classes)) != len(self.classes):
            raise ValueError("supervised category catalog must be unique")
        return self


@dataclass(frozen=True)
class HeadOutputs:
    anomaly_logits: Tensor
    category_logits: Tensor
    severity_logits: Tensor
    line_logits: Tensor
    embeddings: Tensor
    block_attention: tuple[Tensor, ...]
    contrastive_margin: float


@dataclass(frozen=True)
class SupervisedTargets:
    anomaly: Tensor
    categories: Tensor
    severity: Tensor
    lines: Tensor
    similarity_groups: tuple[str | None, ...]


@dataclass(frozen=True)
class MultiTaskLoss:
    total: Tensor
    components: dict[str, Tensor | None]
    supervised_counts: dict[str, int]


class MultiTaskHeads(nn.Module):
    """Residual low-rank feature adapter, block attention, five learned outputs.

    Inputs are source-aligned embeddings from an upstream encoder, not raw metadata.
    Frozen features can train the adapter/heads without changing encoder weights.
    Attention weights are pooling diagnostics, not causal evidence or findings.
    """

    def __init__(self, hidden_size: int, policy: HeadPolicy) -> None:
        super().__init__()
        if type(hidden_size) is not int or not 16 <= hidden_size <= 512:
            raise ValueError("supervised hidden size must be in the supported encoder range")
        self.policy = HeadPolicy.model_validate(policy.model_dump())
        if self.policy.adapter_rank > hidden_size:
            raise ValueError("residual adapter rank must not exceed encoder hidden size")
        self.hidden_size = hidden_size
        self.adapter = nn.Sequential(
            nn.Linear(hidden_size, policy.adapter_rank),
            nn.GELU(),
            nn.Linear(policy.adapter_rank, hidden_size),
        )
        nn.init.zeros_(cast(nn.Linear, self.adapter[2]).weight)
        nn.init.zeros_(cast(nn.Linear, self.adapter[2]).bias)
        self.pooler = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2), nn.Tanh(), nn.Linear(hidden_size // 2, 1)
        )
        self.anomaly = nn.Linear(hidden_size, 1)
        self.category = nn.Linear(hidden_size, len(policy.classes))
        self.severity = nn.Linear(hidden_size, len(SEVERITY_CLASSES))
        self.localizer = nn.Linear(hidden_size, 1)
        self.embedding = nn.Linear(hidden_size, policy.embedding_size)

    def _validate_features(self, blocks: tuple[Tensor, ...], lines: tuple[Tensor, ...]) -> None:
        if not blocks or len(blocks) != len(lines) or len(blocks) > self.policy.max_examples:
            raise ValueError("supervised feature batch is empty, unaligned or exceeds budget")
        expected = self.anomaly.weight
        total = 0
        for block, line in zip(blocks, lines, strict=True):
            for values in (block, line):
                if (
                    not isinstance(values, Tensor)
                    or values.ndim != 2
                    or (
                        values.shape[1] != self.hidden_size
                        or values.dtype != expected.dtype
                        or values.device != expected.device
                        or not bool(torch.isfinite(values).all())
                    )
                ):
                    raise ValueError("supervised features must be finite aligned encoder matrices")
                total += values.numel()
            if not 1 <= block.shape[0] <= self.policy.max_blocks_per_configuration or (
                line.shape[0] > self.policy.max_lines_per_configuration
            ):
                raise ValueError("supervised configuration feature budget exceeded")
        if total > self.policy.max_feature_values:
            raise ValueError("supervised feature value budget exceeded")

    def forward(self, blocks: tuple[Tensor, ...], lines: tuple[Tensor, ...]) -> HeadOutputs:
        self._validate_features(blocks, lines)
        pooled, attention = [], []
        for block in blocks:
            adapted = block + self.adapter(block)
            weights = self.pooler(adapted).squeeze(-1).softmax(dim=0)
            pooled.append((weights.unsqueeze(-1) * adapted).sum(dim=0))
            attention.append(weights)
        configurations = torch.stack(pooled)
        line_features = torch.cat(lines)
        line_features = line_features + self.adapter(line_features)
        return HeadOutputs(
            anomaly_logits=self.anomaly(configurations).squeeze(-1),
            category_logits=self.category(configurations),
            severity_logits=self.severity(configurations),
            line_logits=self.localizer(line_features).squeeze(-1),
            embeddings=nn.functional.normalize(self.embedding(configurations), dim=1),
            block_attention=tuple(attention),
            contrastive_margin=self.policy.contrastive_margin,
        )


def _validate_targets(output: HeadOutputs, targets: SupervisedTargets) -> None:
    if (
        output.anomaly_logits.ndim != 1
        or output.category_logits.ndim != 2
        or len(output.category_logits) != len(output.anomaly_logits)
        or (
            output.severity_logits.shape != (len(output.anomaly_logits), len(SEVERITY_CLASSES))
            or output.line_logits.ndim != 1
            or output.embeddings.ndim != 2
            or len(output.embeddings) != len(output.anomaly_logits)
        )
    ):
        raise ValueError("supervised output shapes are inconsistent")
    pairs = (
        (output.anomaly_logits, targets.anomaly),
        (output.category_logits, targets.categories),
        (output.line_logits, targets.lines),
    )
    for logits, labels in pairs:
        if (
            logits.shape != labels.shape
            or logits.dtype != labels.dtype
            or (
                logits.device != labels.device
                or not bool(torch.isfinite(logits).all())
                or not bool(torch.isfinite(labels).all())
            )
            or not bool(((labels == 0) | (labels == 1) | (labels == IGNORE_TARGET)).all())
        ):
            raise ValueError("binary targets must be aligned finite 0/1 or explicitly ignored")
    severity = targets.severity
    if (
        severity.shape != output.anomaly_logits.shape
        or severity.dtype != torch.long
        or (severity.device != output.severity_logits.device)
        or not bool(((severity == IGNORE_TARGET) | ((severity >= 0) & (severity < 5))).all())
    ):
        raise ValueError("severity targets must be aligned reviewed classes or explicitly ignored")
    if not bool(torch.isfinite(output.severity_logits).all()) or not bool(
        torch.isfinite(output.embeddings).all()
    ):
        raise ValueError("supervised outputs must be finite")
    if bool(((targets.categories == 1).any(dim=1) & (targets.anomaly != 1)).any()) or bool(
        ((severity != IGNORE_TARGET) & (targets.anomaly != 1)).any()
    ):
        raise ValueError("positive category/severity annotations require positive anomaly truth")
    if len(targets.similarity_groups) != len(output.anomaly_logits) or any(
        value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128)
        for value in targets.similarity_groups
    ):
        raise ValueError("reviewed similarity groups must align with the feature batch")


def multitask_loss(
    output: HeadOutputs,
    targets: SupervisedTargets,
    weights: LossWeights,
) -> MultiTaskLoss:
    """L=w1 anomaly+w2 category+w3 localization+w4 severity+w5 contrastive.

    Ignored labels are never negative targets. A required task without supervision
    fails explicitly; callers must choose and record a zero weight to disable it.
    """
    weights = LossWeights.model_validate(weights.model_dump())
    _validate_targets(output, targets)
    components: dict[str, Tensor | None] = {}
    counts = {}
    for name, logits, labels in (
        ("anomaly", output.anomaly_logits, targets.anomaly),
        ("category", output.category_logits, targets.categories),
        ("localization", output.line_logits, targets.lines),
    ):
        mask = labels != IGNORE_TARGET
        counts[name] = int(mask.sum())
        components[name] = (
            nn.functional.binary_cross_entropy_with_logits(logits[mask], labels[mask])
            if counts[name]
            else None
        )
    mask = targets.severity != IGNORE_TARGET
    counts["severity"] = int(mask.sum())
    components["severity"] = (
        nn.functional.cross_entropy(output.severity_logits[mask], targets.severity[mask])
        if counts["severity"]
        else None
    )
    left, right, pair_labels = [], [], []
    groups = targets.similarity_groups
    for index, group in enumerate(groups):
        if group is None:
            continue
        for other in range(index + 1, len(groups)):
            if groups[other] is not None:
                left.append(index)
                right.append(other)
                pair_labels.append(1 if group == groups[other] else -1)
    counts["contrastive"] = len(pair_labels)
    components["contrastive"] = (
        nn.functional.cosine_embedding_loss(
            output.embeddings[left],
            output.embeddings[right],
            torch.tensor(
                pair_labels, dtype=output.embeddings.dtype, device=output.embeddings.device
            ),
            margin=output.contrastive_margin,
        )
        if 1 in pair_labels and -1 in pair_labels
        else None
    )
    active = []
    for name, weight in weights.model_dump().items():
        if weight:
            loss = components[name]
            if loss is None:
                raise ValueError(f"required {name} objective has no usable supervision")
            if not bool(torch.isfinite(loss)):
                raise ValueError("nonfinite supervised objective")
            active.append(weight * loss)
    total = torch.stack(active).sum()
    return MultiTaskLoss(total=total, components=components, supervised_counts=counts)
