"""Frozen-encoder probe for single injected mutations, not production risk."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import torch
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sklearn.metrics import average_precision_score
from torch import Tensor, nn

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.mutation import MutationNotApplicableError, MutationType, mutate_configuration
from ml.preprocessing.blocks import digest, segment_configuration
from ml.preprocessing.tokenization import TokenizerArtifact, _validate_split_entities, encode_block
from ml.training.checkpoint import load_checkpoint, save_checkpoint
from ml.training.transformer import ConfigEncoderMLM, TrainingReport, TrainingResult

REFERENCE_CLASS = "no_injected_mutation"


class ProbePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    seed: int = Field(default=17, ge=0, le=2**31 - 1)
    epochs: int = Field(default=20, ge=1, le=1000)
    learning_rate: float = Field(default=0.01, gt=0, le=0.1)
    max_examples: int = Field(default=1000, ge=1, le=100000)
    max_windows: int = Field(default=10000, ge=1, le=100000)
    batch_size: int = Field(default=16, ge=1, le=64)


@dataclass(frozen=True)
class ProbeExample:
    record: ImportedDatasetRecord
    label: int
    mutation_id: str | None
    parent_sha256: str


class ClassMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    label: str
    support: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    average_precision: float | None = Field(default=None, ge=0, le=1)


class ProbeReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["synthetic-probe-0.1.0"] = "synthetic-probe-0.1.0"
    policy: ProbePolicy
    classes: tuple[str, ...]
    encoder_sha256: str
    train_fingerprint: str
    validation_fingerprint: str
    train_examples: int = Field(ge=1)
    validation_examples: int = Field(ge=1)
    skipped_not_applicable: dict[str, int]
    losses: tuple[tuple[float, float], ...]
    best_epoch: int
    validation_metrics: tuple[ClassMetrics, ...]
    macro_f1: float = Field(ge=0, le=1)
    synthetic_only: Literal[True] = True
    test_evaluated: Literal[False] = False
    encoder_frozen: Literal[True] = True

    @model_validator(mode="after")
    def consistent_report(self) -> ProbeReport:
        if not self.classes or self.classes[0] != REFERENCE_CLASS:
            raise ValueError("first class must be the unmodified reference")
        if len(self.classes) < 2 or len(set(self.classes)) != len(self.classes):
            raise ValueError("classes must be unique and include a mutation")
        for name in self.classes[1:]:
            MutationType(name)
        if len(self.losses) != self.policy.epochs or any(
            loss < 0 for pair in self.losses for loss in pair
        ):
            raise ValueError("losses must cover every epoch")
        if self.best_epoch != min(range(len(self.losses)), key=lambda i: self.losses[i][1]) + 1:
            raise ValueError("best epoch must minimize validation loss")
        if tuple(item.label for item in self.validation_metrics) != self.classes:
            raise ValueError("metrics must follow class order")
        if sum(item.support for item in self.validation_metrics) != self.validation_examples:
            raise ValueError("metric support must match validation size")
        if (
            abs(
                self.macro_f1 - sum(item.f1 for item in self.validation_metrics) / len(self.classes)
            )
            > 1e-9
        ):
            raise ValueError("macro F1 must match class metrics")
        return self


@dataclass
class ProbeResult:
    pretrained: TrainingResult
    head: nn.Linear
    report: ProbeReport


def prepare_examples(
    splits: DatasetSplitResult,
    mutation_types: tuple[MutationType, ...],
    policy: ProbePolicy,
) -> tuple[dict[DatasetSplit, list[ProbeExample]], dict[str, int]]:
    """Generate after splitting; each child stays with its parent, never use test."""
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    _validate_split_entities(splits)
    if not mutation_types or len(set(mutation_types)) != len(mutation_types):
        raise ValueError("mutation classes must be nonempty and unique")
    examples: dict[DatasetSplit, list[ProbeExample]] = {}
    skipped: dict[str, int] = {}
    hashes: dict[str, tuple[DatasetSplit, int]] = {
        record.sanitized_sha256: (DatasetSplit.TEST, -1)
        for partition in splits.partitions
        if partition.split is DatasetSplit.TEST
        for record in partition.records
    }
    for partition in splits.partitions:
        if partition.split is DatasetSplit.TEST:
            continue
        rows: list[ProbeExample] = []
        for record in sorted(partition.records, key=lambda item: (item.source_id, item.record_id)):
            if digest(record.sanitized_text) != record.sanitized_sha256:
                raise ValueError("source text checksum mismatch")
            rows.append(ProbeExample(record, 0, None, record.sanitized_sha256))
            for label, mutation in enumerate(mutation_types, 1):
                try:
                    sample = mutate_configuration(record, (mutation,), seed=policy.seed)
                except MutationNotApplicableError:
                    key = f"{partition.split}:{mutation}"
                    skipped[key] = skipped.get(key, 0) + 1
                    continue
                mutated = record.model_copy(
                    update={
                        "sanitized_text": sample.mutated_text,
                        "sanitized_sha256": sample.mutated_sha256,
                    }
                )
                rows.append(
                    ProbeExample(mutated, label, sample.mutation_id, sample.original_sha256)
                )
            if len(rows) > policy.max_examples:
                raise ValueError("classification example budget exceeded")
        # Catch identical derived configurations crossing partitions too.
        for row in rows:
            previous = hashes.setdefault(row.record.sanitized_sha256, (partition.split, row.label))
            if previous[0] != partition.split:
                raise ValueError("derived configuration leaks across partitions")
            if previous[1] != row.label:
                raise ValueError("identical configurations have conflicting labels")
        examples[partition.split] = rows
    if {item.label for item in examples[DatasetSplit.TRAIN]} != set(range(len(mutation_types) + 1)):
        raise ValueError("every requested class needs a training example")
    return examples, skipped


def _fingerprint(rows: list[ProbeExample]) -> str:
    return digest(
        json.dumps(
            [
                (
                    row.record.source_id,
                    row.record.record_id,
                    row.parent_sha256,
                    row.record.sanitized_sha256,
                    row.label,
                    row.mutation_id,
                )
                for row in rows
            ],
            separators=(",", ":"),
        )
    )


def _encoder_hash(model: ConfigEncoderMLM) -> str:
    checksum = hashlib.sha256()
    for name, value in sorted(model.state_dict().items()):
        checksum.update(name.encode())
        checksum.update(str(tuple(value.shape)).encode())
        checksum.update(value.detach().cpu().contiguous().numpy().tobytes())
    return checksum.hexdigest()


def _features(
    rows: list[ProbeExample],
    pretrained: TrainingResult,
    policy: ProbePolicy,
) -> Tensor:
    model = pretrained.model
    features = []
    window_count = 0
    with torch.no_grad():
        for row in rows:
            total = torch.zeros(pretrained.report.encoder_policy.hidden_size)
            count = 0
            for block in segment_configuration(row.record):
                windows = encode_block(block, pretrained.tokenizer)
                window_count += len(windows)
                if window_count > policy.max_windows:
                    raise ValueError("classification window budget exceeded")
                for offset in range(0, len(windows), policy.batch_size):
                    batch = windows[offset : offset + policy.batch_size]
                    ids = torch.tensor([item.input_ids for item in batch])
                    attention = torch.tensor([item.attention_mask for item in batch])
                    content = attention.bool() & (ids >= 5)
                    hidden = model.encode(ids, attention)
                    total += (hidden * content.unsqueeze(-1)).sum(dim=(0, 1))
                    count += int(content.sum())
            if not count:
                raise ValueError("configuration has no content tokens")
            features.append(total / count)
    return torch.stack(features)


def _metrics(
    probabilities: Tensor, labels: Tensor, classes: tuple[str, ...]
) -> tuple[ClassMetrics, ...]:
    predictions = probabilities.argmax(dim=1)
    result = []
    for index, name in enumerate(classes):
        truth, predicted = labels == index, predictions == index
        tp = int((truth & predicted).sum())
        support, selected = int(truth.sum()), int(predicted.sum())
        precision, recall = tp / max(selected, 1), tp / max(support, 1)
        result.append(
            ClassMetrics(
                label=name,
                support=support,
                precision=precision,
                recall=recall,
                f1=2 * precision * recall / (precision + recall) if precision + recall else 0,
                average_precision=float(
                    average_precision_score(truth.numpy(), probabilities[:, index].numpy())
                )
                if 0 < support < len(labels)
                else None,
            )
        )
    return tuple(result)


def train_mutation_probe(
    splits: DatasetSplitResult,
    pretrained: TrainingResult,
    mutation_types: tuple[MutationType, ...],
    *,
    policy: ProbePolicy | None = None,
) -> ProbeResult:
    """Train only a linear head; validation selects epoch, no calibrated risk."""
    policy = ProbePolicy.model_validate((policy or ProbePolicy()).model_dump())
    tokenizer = TokenizerArtifact.model_validate(pretrained.tokenizer.model_dump())
    pretraining_report = TrainingReport.model_validate(pretrained.report.model_dump())
    if tokenizer.tokenizer_sha256 != pretraining_report.tokenizer_sha256:
        raise ValueError("pretrained tokenizer does not match training report")
    rows, skipped = prepare_examples(splits, mutation_types, policy)
    train_records = sorted(
        (row.record for row in rows[DatasetSplit.TRAIN] if row.label == 0),
        key=lambda item: (item.source_id, item.record_id),
    )
    fingerprint = digest(
        json.dumps(
            [(row.source_id, row.record_id, row.sanitized_sha256) for row in train_records],
            separators=(",", ":"),
        )
    )
    if fingerprint != pretrained.tokenizer.training_fingerprint or (
        fingerprint != pretrained.report.training_fingerprint
    ):
        raise ValueError("pretrained encoder belongs to a different training corpus")
    validation_records = [row.record for row in rows[DatasetSplit.VALIDATION] if row.label == 0]
    validation_fingerprint = digest(
        json.dumps(
            [(row.source_id, row.record_id, row.sanitized_sha256) for row in validation_records],
            separators=(",", ":"),
        )
    )
    if validation_fingerprint != pretrained.report.validation_fingerprint:
        raise ValueError("pretrained encoder belongs to a different validation corpus")
    # Copy so training/eval state and gradients of the caller's model are untouched.
    pretrained = TrainingResult(
        copy.deepcopy(pretrained.model), pretrained.tokenizer, pretrained.report
    )
    pretrained.model.cpu().eval().requires_grad_(False)
    classes = (REFERENCE_CLASS, *(item.value for item in mutation_types))
    threads = torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    warn_only = torch.is_deterministic_algorithms_warn_only_enabled()
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(policy.seed)
            x_train = _features(rows[DatasetSplit.TRAIN], pretrained, policy)
            x_val = _features(rows[DatasetSplit.VALIDATION], pretrained, policy)
            y_train = torch.tensor([row.label for row in rows[DatasetSplit.TRAIN]])
            y_val = torch.tensor([row.label for row in rows[DatasetSplit.VALIDATION]])
            head = nn.Linear(x_train.shape[1], len(classes))
            optimizer = torch.optim.AdamW(head.parameters(), lr=policy.learning_rate)
            losses = []
            best_loss = float("inf")
            best_epoch = 0
            best_weights: dict[str, Tensor] = {}
            for epoch in range(1, policy.epochs + 1):
                optimizer.zero_grad(set_to_none=True)
                loss = nn.functional.cross_entropy(head(x_train), y_train)
                if not torch.isfinite(loss):
                    raise ValueError("non-finite classification loss")
                loss.backward()  # type: ignore[no-untyped-call]
                nn.utils.clip_grad_norm_(head.parameters(), 1, error_if_nonfinite=True)
                optimizer.step()
                with torch.no_grad():
                    val_loss = float(nn.functional.cross_entropy(head(x_val), y_val))
                if not torch.isfinite(torch.tensor(val_loss)):
                    raise ValueError("non-finite validation loss")
                losses.append((float(loss.detach()), val_loss))
                if val_loss < best_loss:
                    best_loss, best_epoch = val_loss, epoch
                    best_weights = {
                        name: value.detach().clone() for name, value in head.state_dict().items()
                    }
            head.load_state_dict(best_weights)
            head.eval()
            with torch.no_grad():
                metrics = _metrics(head(x_val).softmax(dim=1), y_val, classes)
    finally:
        torch.set_num_threads(threads)
        torch.use_deterministic_algorithms(deterministic, warn_only=warn_only)
    report = ProbeReport(
        policy=policy,
        classes=classes,
        encoder_sha256=_encoder_hash(pretrained.model),
        train_fingerprint=_fingerprint(rows[DatasetSplit.TRAIN]),
        validation_fingerprint=_fingerprint(rows[DatasetSplit.VALIDATION]),
        train_examples=len(x_train),
        validation_examples=len(x_val),
        skipped_not_applicable=skipped,
        losses=tuple(losses),
        best_epoch=best_epoch,
        validation_metrics=metrics,
        macro_f1=sum(item.f1 for item in metrics) / len(metrics),
    )
    return ProbeResult(pretrained, head, report)


def predict_mutations(result: ProbeResult, record: ImportedDatasetRecord) -> dict[str, float]:
    """Uncalibrated class probabilities; reference does not mean healthy."""
    if result.pretrained.model.training or result.head.training:
        raise ValueError("prediction requires evaluation mode")
    features = _features(
        [ProbeExample(record, 0, None, record.sanitized_sha256)],
        result.pretrained,
        result.report.policy,
    )
    with torch.no_grad():
        values = result.head(features).softmax(dim=1)[0].tolist()
    return dict(zip(result.report.classes, values, strict=True))


def save_probe(result: ProbeResult, path: Path) -> None:
    """New local bundle, reusing the verified MLM checkpoint format."""
    path.mkdir(exist_ok=False)
    save_checkpoint(result.pretrained, path / "encoder")
    payload = {
        "report": result.report.model_dump(mode="json"),
        "weight": result.head.weight.detach().tolist(),
        "bias": result.head.bias.detach().tolist(),
    }
    text = json.dumps(payload, sort_keys=True, allow_nan=False)
    (path / "classifier.json").write_text(text, encoding="utf-8")
    (path / "classifier.sha256").write_text(digest(text), encoding="ascii")


def load_probe(path: Path) -> ProbeResult:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("unsafe probe directory")
    if {item.name for item in path.iterdir()} != {
        "encoder",
        "classifier.json",
        "classifier.sha256",
    }:
        raise ValueError("incomplete probe bundle")
    for name in ("classifier.json", "classifier.sha256"):
        item = path / name
        if item.is_symlink() or not item.is_file() or item.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("unsafe probe file")
    text = (path / "classifier.json").read_text(encoding="utf-8")
    if digest(text) != (path / "classifier.sha256").read_text(encoding="ascii"):
        raise ValueError("probe checksum mismatch")
    payload = json.loads(text)
    report = ProbeReport.model_validate(payload["report"])
    pretrained = load_checkpoint(path / "encoder")
    if _encoder_hash(pretrained.model) != report.encoder_sha256:
        raise ValueError("probe encoder checksum mismatch")
    with torch.random.fork_rng(devices=[]):
        head = nn.Linear(pretrained.report.encoder_policy.hidden_size, len(report.classes))
    head.load_state_dict(
        {"weight": torch.tensor(payload["weight"]), "bias": torch.tensor(payload["bias"])}
    )
    if any(not torch.isfinite(value).all() for value in head.state_dict().values()):
        raise ValueError("non-finite probe weights")
    pretrained.model.requires_grad_(False)
    return ProbeResult(pretrained, head.eval(), report)
