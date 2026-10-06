"""Joint, bounded CPU pretraining with explicit construction and semantic-label exposure."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

import torch
from pydantic import BaseModel, ConfigDict, Field, model_validator
from torch import Tensor, nn

from ml.datasets import DatasetSplit, DatasetSplitResult
from ml.evaluation.cli import _unique_pairs
from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.tokenization import (
    TokenizerArtifact,
    TokenWindow,
    load_tokenizer,
    save_tokenizer,
)
from ml.training.checkpoint import _file_hash
from ml.training.masking import IGNORE_LABEL
from ml.training.pretraining_data import (
    TASKS,
    ObjectiveData,
    PretrainingWeights,
    SemanticPair,
    prepare_pretraining,
)
from ml.training.transformer import ConfigEncoderMLM, EncoderPolicy


class PretrainingPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    seed: int = Field(default=17, ge=0, le=2**31 - 1, strict=True)
    epochs: int = Field(default=10, ge=1, le=100, strict=True)
    batch_size: int = Field(default=8, ge=1, le=64, strict=True)
    learning_rate: float = Field(default=0.005, gt=0, le=0.1)
    weight_decay: float = Field(default=0.01, ge=0, le=1)
    gradient_clip: float = Field(default=1, gt=0, le=100)
    contrastive_margin: float = Field(default=0.2, ge=-1, le=1)
    embedding_size: int = Field(default=32, ge=2, le=512, strict=True)
    max_records: int = Field(default=128, ge=1, le=2048, strict=True)
    max_windows: int = Field(default=10000, ge=1, le=100000, strict=True)
    max_examples: int = Field(default=20000, ge=1, le=100000, strict=True)
    max_pair_windows: int = Field(default=256, ge=1, le=2048, strict=True)


class PretrainingEpoch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    epoch: int = Field(ge=1)
    train_components: dict[str, float | None]
    validation_components: dict[str, float | None]
    train_total: float = Field(ge=0)
    validation_total: float = Field(ge=0)


class PretrainingReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["config-objective-pretraining-0.1.0"] = "config-objective-pretraining-0.1.0"
    encoder_policy: EncoderPolicy
    training_policy: PretrainingPolicy
    weights: PretrainingWeights
    tokenizer_sha256: Digest
    train_source_fingerprint: Digest
    validation_source_fingerprint: Digest
    train_fingerprint: Digest
    validation_fingerprint: Digest
    source_counts: dict[str, int]
    train_counts: dict[str, int]
    validation_counts: dict[str, int]
    semantic_scopes: tuple[str, ...]
    semantic_origin_counts: dict[str, int]
    parameter_count: int = Field(ge=1)
    best_epoch: int = Field(ge=1)
    losses: tuple[PretrainingEpoch, ...]
    torch_version: str
    test_evaluated: Literal[False] = False
    production_quality_proven: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self) -> PretrainingReport:
        if (
            tuple(row.epoch for row in self.losses)
            != tuple(range(1, self.training_policy.epochs + 1))
            or self.best_epoch != min(self.losses, key=lambda row: row.validation_total).epoch
        ):
            raise ValueError("pretraining report has invalid epochs or selection")
        if set(self.source_counts) != {"train", "validation"} or any(
            value < 1 for value in self.source_counts.values()
        ):
            raise ValueError("pretraining source counts must identify both partitions")
        for counts in (self.train_counts, self.validation_counts):
            if set(counts) != set(TASKS) or any(value < 0 for value in counts.values()):
                raise ValueError("pretraining target counts must cover all objectives")
            if any(
                weight and not counts[name] for name, weight in self.weights.model_dump().items()
            ):
                raise ValueError("enabled objective lacks measured supervision")
        if (
            len(self.semantic_scopes) > 1
            or (self.weights.cross_vendor and len(self.semantic_scopes) != 1)
            or set(self.semantic_origin_counts) - {"synthetic", "laboratory", "real_confirmed"}
            or any(value < 1 for value in self.semantic_origin_counts.values())
            or sum(self.semantic_origin_counts.values())
            != (self.train_counts["cross_vendor"] + self.validation_counts["cross_vendor"])
        ):
            raise ValueError("semantic exposure counts/scopes are inconsistent")
        for epoch in self.losses:
            for components, total in (
                (epoch.train_components, epoch.train_total),
                (epoch.validation_components, epoch.validation_total),
            ):
                if set(components) != set(TASKS):
                    raise ValueError("pretraining components must cover every objective")
                expected = 0.0
                for name, weight in self.weights.model_dump().items():
                    value = components[name]
                    if weight:
                        if value is None or value < 0:
                            raise ValueError("enabled pretraining component is missing/invalid")
                        expected += weight * value
                    elif value is not None:
                        raise ValueError("disabled pretraining component must remain unmeasured")
                if not math.isclose(expected, total, rel_tol=1e-6, abs_tol=1e-6):
                    raise ValueError("pretraining weighted total differs from components")
        return self


class ObjectiveEncoder(nn.Module):
    def __init__(
        self, tokenizer: TokenizerArtifact, encoder: EncoderPolicy, policy: PretrainingPolicy
    ) -> None:
        super().__init__()
        self.encoder_policy = encoder
        self.training_policy = policy
        self.encoder = ConfigEncoderMLM(
            tokenizer.actual_vocab_size, tokenizer.policy.context_length, encoder
        )
        self.replaced_line = nn.Linear(encoder.hidden_size, 1)
        self.same_device = nn.Sequential(
            nn.Linear(encoder.hidden_size * 2, encoder.hidden_size),
            nn.GELU(),
            nn.Linear(encoder.hidden_size, 1),
        )
        self.projection = nn.Linear(encoder.hidden_size, policy.embedding_size)


@dataclass
class PretrainingResult:
    model: ObjectiveEncoder
    tokenizer: TokenizerArtifact
    report: PretrainingReport


def _pooled(
    model: ObjectiveEncoder, windows: tuple[TokenWindow, ...], policy: PretrainingPolicy
) -> Tensor:
    if not windows or len(windows) > policy.max_pair_windows:
        raise ValueError("pretraining pair window budget exceeded; no truncation")
    total, count = torch.zeros(model.encoder.norm.normalized_shape[0]), 0
    for offset in range(0, len(windows), policy.batch_size):
        batch = windows[offset : offset + policy.batch_size]
        hidden = model.encoder.encode(
            torch.tensor([row.input_ids for row in batch]),
            torch.tensor([row.attention_mask for row in batch]),
        )
        content = torch.tensor(
            [
                [
                    bool(attention and not special)
                    for attention, special in zip(
                        row.attention_mask, row.special_tokens_mask, strict=True
                    )
                ]
                for row in batch
            ]
        )
        total = total + hidden[content].sum(dim=0)
        count += int(content.sum())
    if not count:
        raise ValueError("pretraining pair has no source content")
    return total / count


def _run_objectives(
    model: ObjectiveEncoder,
    data: ObjectiveData,
    policy: PretrainingPolicy,
    weights: PretrainingWeights,
    *,
    backward: bool,
) -> tuple[dict[str, float | None], float]:
    """Accumulate exact weighted objective means; one optimizer step per epoch."""
    counts = data.counts()
    components: dict[str, float | None] = {}
    total = 0.0

    def add(name: str, loss_sum: Tensor) -> None:
        nonlocal total
        if not bool(torch.isfinite(loss_sum)):
            raise ValueError("nonfinite pretraining objective")
        value = float(loss_sum.detach()) / counts[name]
        components[name] = cast(float, components[name]) + value
        weight = cast(float, getattr(weights, name))
        total += weight * value
        if backward:
            (loss_sum * weight / counts[name]).backward()  # type: ignore[no-untyped-call]

    for name in TASKS:
        if not getattr(weights, name):
            components[name] = None
            continue
        components[name] = 0.0
        if name in TASKS[:3]:
            rows = getattr(data, name)
            for offset in range(0, len(rows), policy.batch_size):
                batch = rows[offset : offset + policy.batch_size]
                logits = model.encoder(
                    torch.tensor([row.input_ids for row in batch]),
                    torch.tensor([row.attention_mask for row in batch]),
                )
                labels = torch.tensor([row.labels for row in batch])
                add(
                    name,
                    nn.functional.cross_entropy(
                        logits.reshape(-1, logits.shape[-1]),
                        labels.reshape(-1),
                        ignore_index=IGNORE_LABEL,
                        reduction="sum",
                    ),
                )
        elif name == "replaced_line":
            for offset in range(0, len(data.replaced_line), policy.batch_size):
                line_batch = data.replaced_line[offset : offset + policy.batch_size]
                hidden = model.encoder.encode(
                    torch.tensor([row.window.input_ids for row in line_batch]),
                    torch.tensor([row.window.attention_mask for row in line_batch]),
                )
                vectors = torch.stack(
                    [
                        hidden[index, list(row.positions)].mean(dim=0)
                        for index, row in enumerate(line_batch)
                    ]
                )
                logits = model.replaced_line(vectors).squeeze(-1)
                targets = torch.tensor([float(row.replaced) for row in line_batch])
                add(
                    name,
                    nn.functional.binary_cross_entropy_with_logits(
                        logits, targets, reduction="sum"
                    ),
                )
        else:
            for pair in getattr(data, name):
                left, right = _pooled(model, pair.left, policy), _pooled(model, pair.right, policy)
                if name == "same_device":
                    logits = model.same_device(
                        torch.cat((abs(left - right), left * right))
                    ).squeeze()
                    add(
                        name,
                        nn.functional.binary_cross_entropy_with_logits(
                            logits, torch.tensor(float(pair.positive)), reduction="sum"
                        ),
                    )
                else:
                    left = nn.functional.normalize(model.projection(left), dim=0)
                    right = nn.functional.normalize(model.projection(right), dim=0)
                    add(
                        name,
                        nn.functional.cosine_embedding_loss(
                            left.unsqueeze(0),
                            right.unsqueeze(0),
                            torch.tensor([1.0 if pair.positive else -1.0]),
                            margin=policy.contrastive_margin,
                            reduction="sum",
                        ),
                    )
    return components, total


def train_configuration_objectives(
    splits: DatasetSplitResult,
    tokenizer: TokenizerArtifact,
    *,
    encoder_policy: EncoderPolicy | None = None,
    training_policy: PretrainingPolicy | None = None,
    weights: PretrainingWeights | None = None,
    semantic_pairs: tuple[SemanticPair, ...] = (),
) -> PretrainingResult:
    """Train the encoder jointly on declared tasks; test data never supplies targets."""
    encoder = EncoderPolicy.model_validate((encoder_policy or EncoderPolicy()).model_dump())
    policy = PretrainingPolicy.model_validate((training_policy or PretrainingPolicy()).model_dump())
    weights = PretrainingWeights.model_validate((weights or PretrainingWeights()).model_dump())
    tokenizer = TokenizerArtifact.model_validate(tokenizer.model_dump())
    data = prepare_pretraining(
        splits,
        tokenizer,
        seed=policy.seed,
        semantic_pairs=semantic_pairs,
        max_records=policy.max_records,
        max_windows=policy.max_windows,
        max_examples=policy.max_examples,
    )
    for part in data.values():
        counts = part.counts()
        for name, weight in weights.model_dump().items():
            if weight and not counts[name]:
                raise ValueError(f"enabled pretraining objective has no {name} targets")
            if (
                weight
                and name in TASKS[3:]
                and {
                    getattr(row, "replaced" if name == "replaced_line" else "positive")
                    for row in getattr(part, name)
                }
                != {False, True}
            ):
                raise ValueError(
                    "binary/contrastive objective requires positive and negative targets"
                )
        for pair in (*part.same_device, *part.cross_vendor):
            if max(len(pair.left), len(pair.right)) > policy.max_pair_windows:
                raise ValueError("pretraining pair window budget exceeded")
    previous_threads = torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    warn = torch.is_deterministic_algorithms_warn_only_enabled()
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(policy.seed)
            model = ObjectiveEncoder(tokenizer, encoder, policy)
            optimizer = torch.optim.AdamW(
                model.parameters(), lr=policy.learning_rate, weight_decay=policy.weight_decay
            )
            epochs, best, selected, state = [], float("inf"), 0, {}
            for epoch in range(1, policy.epochs + 1):
                model.train()
                optimizer.zero_grad(set_to_none=True)
                train_components, train_total = _run_objectives(
                    model, data[DatasetSplit.TRAIN], policy, weights, backward=True
                )
                nn.utils.clip_grad_norm_(
                    model.parameters(), policy.gradient_clip, error_if_nonfinite=True
                )
                optimizer.step()
                model.eval()
                with torch.no_grad():
                    val_components, val_total = _run_objectives(
                        model, data[DatasetSplit.VALIDATION], policy, weights, backward=False
                    )
                epochs.append(
                    PretrainingEpoch(
                        epoch=epoch,
                        train_components=train_components,
                        train_total=train_total,
                        validation_components=val_components,
                        validation_total=val_total,
                    )
                )
                if val_total < best:
                    best, selected = val_total, epoch
                    state = {
                        name: value.detach().clone() for name, value in model.state_dict().items()
                    }
            model.load_state_dict(state)
            model.eval()
    finally:
        torch.use_deterministic_algorithms(deterministic, warn_only=warn)
        torch.set_num_threads(previous_threads)
    train, validation = data[DatasetSplit.TRAIN], data[DatasetSplit.VALIDATION]
    report = PretrainingReport(
        encoder_policy=encoder,
        training_policy=policy,
        weights=weights,
        tokenizer_sha256=tokenizer.tokenizer_sha256,
        train_source_fingerprint=train.source_fingerprint,
        validation_source_fingerprint=validation.source_fingerprint,
        train_fingerprint=train.fingerprint,
        validation_fingerprint=validation.fingerprint,
        source_counts={"train": train.records, "validation": validation.records},
        train_counts=train.counts(),
        validation_counts=validation.counts(),
        semantic_scopes=train.semantic_scopes,
        semantic_origin_counts={
            origin: sum(pair.origin == origin for pair in semantic_pairs)
            for origin in sorted({pair.origin for pair in semantic_pairs})
        },
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        best_epoch=selected,
        losses=tuple(epochs),
        torch_version=torch.__version__,
    )
    return PretrainingResult(model, tokenizer, report)


def save_pretraining(result: PretrainingResult, path: Path) -> None:
    report = PretrainingReport.model_validate(result.report.model_dump())
    tokenizer = TokenizerArtifact.model_validate(result.tokenizer.model_dump())
    if report.tokenizer_sha256 != tokenizer.tokenizer_sha256 or (
        report.train_source_fingerprint != tokenizer.training_fingerprint
        or report.encoder_policy != result.model.encoder_policy
        or report.training_policy != result.model.training_policy
        or report.parameter_count
        != sum(parameter.numel() for parameter in result.model.parameters())
        or any(
            not bool(torch.isfinite(value).all()) for value in result.model.state_dict().values()
        )
    ):
        raise ValueError("pretraining bundle model/report/tokenizer binding is invalid")
    path.mkdir(exist_ok=False)
    marker = path / ".incomplete"
    marker.write_text("pretraining bundle writing\n", encoding="utf-8")
    save_tokenizer(tokenizer, path / "tokenizer.json")
    (path / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    with (path / "weights.pt").open("xb") as target:
        torch.save(result.model.state_dict(), target)
    manifest = {
        "version": report.version,
        "files": {
            name: _file_hash(path / name)
            for name in ("tokenizer.json", "report.json", "weights.pt")
        },
    }
    (path / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    marker.unlink()


def load_pretraining(path: Path) -> PretrainingResult:
    files = {"tokenizer.json", "report.json", "weights.pt", "manifest.json"}
    if path.is_symlink() or not path.is_dir() or {item.name for item in path.iterdir()} != files:
        raise ValueError("pretraining bundle is missing, unsafe or incomplete")
    for item in path.iterdir():
        limit = 512 * 1024 * 1024 if item.name == "weights.pt" else 16 * 1024 * 1024
        if item.is_symlink() or not item.is_file() or item.stat().st_size > limit:
            raise ValueError("unsafe pretraining bundle file")
    manifest = json.loads(
        (path / "manifest.json").read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"version", "files"}
        or (
            manifest["version"] != "config-objective-pretraining-0.1.0"
            or not isinstance(manifest["files"], dict)
            or set(manifest["files"]) != files - {"manifest.json"}
            or any(_file_hash(path / name) != value for name, value in manifest["files"].items())
        )
    ):
        raise ValueError("pretraining bundle manifest/checksum mismatch")
    payload = json.loads(
        (path / "report.json").read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs
    )
    report = PretrainingReport.model_validate(payload)
    tokenizer = load_tokenizer(path / "tokenizer.json")
    if report.tokenizer_sha256 != tokenizer.tokenizer_sha256 or (
        report.train_source_fingerprint != tokenizer.training_fingerprint
    ):
        raise ValueError("pretraining bundle tokenizer/report mismatch")
    with torch.random.fork_rng(devices=[]):
        model = ObjectiveEncoder(tokenizer, report.encoder_policy, report.training_policy)
    if sum(parameter.numel() for parameter in model.parameters()) != report.parameter_count:
        raise ValueError("pretraining bundle parameter count mismatch")
    model.load_state_dict(
        torch.load(path / "weights.pt", map_location="cpu", weights_only=True), strict=True
    )
    if any(not bool(torch.isfinite(value).all()) for value in model.state_dict().values()):
        raise ValueError("pretraining bundle has nonfinite weights")
    return PretrainingResult(model.eval(), tokenizer, report)


def pretraining_identity(result: PretrainingResult) -> str:
    checksum = hashlib.sha256()
    for name, value in sorted(result.model.state_dict().items()):
        checksum.update(json.dumps((name, tuple(value.shape), str(value.dtype))).encode())
        checksum.update(value.detach().cpu().contiguous().numpy().tobytes())
    return canonical_hash(
        {
            "report": result.report.model_dump(mode="json"),
            "weights_sha256": checksum.hexdigest(),
        }
    )
