"""Synthetic changed-line localization with a frozen encoder and linear head."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Literal

import torch
from pydantic import BaseModel, ConfigDict, Field, model_validator
from torch import Tensor, nn

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest, segment_configuration
from ml.preprocessing.tokenization import encode_block
from ml.training.checkpoint import load_checkpoint, save_checkpoint
from ml.training.classification import (
    ClassMetrics,
    ProbeExample,
    ProbePolicy,
    _encoder_hash,
    _fingerprint,
    _metrics,
    prepare_examples,
    validate_pretrained_corpus,
)
from ml.training.transformer import TrainingResult


class LinePolicy(ProbePolicy):
    max_lines: int = Field(default=50000, ge=1, le=500000)


@dataclass(frozen=True)
class LineTargets:
    changed_lines: tuple[int, ...]
    ignored_lines: tuple[int, ...]
    deleted_lines: int


def line_targets(original: str, current: str) -> LineTargets:
    """Use current-file coordinates; deletion anchors are not positive labels."""
    before, after = original.splitlines(), current.splitlines()
    positive: set[int] = set()
    ignored: set[int] = set()
    deleted = 0
    for tag, left, left_end, right, right_end in SequenceMatcher(
        a=before, b=after, autojunk=False
    ).get_opcodes():
        if tag in {"insert", "replace"}:
            positive.update(range(right + 1, right_end + 1))
        elif tag == "delete":
            deleted += left_end - left
            # Both sides of a missing-command gap are ambiguous, not faulty lines.
            ignored.update(line for line in (right, right + 1) if 1 <= line <= len(after))
    return LineTargets(tuple(sorted(positive)), tuple(sorted(ignored - positive)), deleted)


class LineReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["synthetic-lines-0.1.0"] = "synthetic-lines-0.1.0"
    policy: LinePolicy
    mutation_types: tuple[MutationType, ...]
    encoder_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    train_fingerprint: str
    validation_fingerprint: str
    train_lines: int = Field(ge=1)
    validation_lines: int = Field(ge=1)
    train_positive_lines: int = Field(ge=1)
    validation_positive_lines: int = Field(ge=1)
    positive_weight: float = Field(gt=0)
    excluded_deletion_only: dict[str, int]
    skipped_not_applicable: dict[str, int]
    losses: tuple[tuple[float, float], ...]
    best_epoch: int = Field(ge=1)
    validation_metrics: tuple[ClassMetrics, ...]
    threshold: float = Field(default=0.5, ge=0.5, le=0.5)
    synthetic_only: Literal[True] = True
    test_evaluated: Literal[False] = False
    encoder_frozen: Literal[True] = True

    @model_validator(mode="after")
    def consistent_report(self) -> LineReport:
        if not self.mutation_types or len(set(self.mutation_types)) != len(self.mutation_types):
            raise ValueError("mutation types must be nonempty and unique")
        if len(self.losses) != self.policy.epochs or any(
            x < 0 for pair in self.losses for x in pair
        ):
            raise ValueError("losses must cover each epoch")
        if self.best_epoch != min(range(len(self.losses)), key=lambda i: self.losses[i][1]) + 1:
            raise ValueError("best epoch must minimize validation loss")
        if not 0 < self.train_positive_lines < self.train_lines:
            raise ValueError("training requires positive and negative lines")
        if not 0 < self.validation_positive_lines < self.validation_lines:
            raise ValueError("validation requires positive and negative lines")
        expected_weight = (self.train_lines - self.train_positive_lines) / self.train_positive_lines
        if abs(self.positive_weight - expected_weight) > 1e-9:
            raise ValueError("class weight must come from training lines only")
        if tuple(item.label for item in self.validation_metrics) != ("unchanged", "changed"):
            raise ValueError("unexpected line metric labels")
        if tuple(item.support for item in self.validation_metrics) != (
            self.validation_lines - self.validation_positive_lines,
            self.validation_positive_lines,
        ):
            raise ValueError("line metric support mismatch")
        return self


@dataclass
class LineResult:
    pretrained: TrainingResult
    head: nn.Linear
    report: LineReport


class LineScore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    source_sha256: str
    line_number: int = Field(ge=1)
    changed_score: float | None = Field(ge=0, le=1)
    predicted_changed: bool | None


def _line_features(
    record: ImportedDatasetRecord,
    pretrained: TrainingResult,
    policy: LinePolicy,
    budget: list[int],
) -> tuple[Tensor, Tensor]:
    """Pool source-aligned tokens; share multi-line token weight equally."""
    line_count = len(record.sanitized_text.splitlines())
    budget[0] += line_count
    if budget[0] > policy.max_lines:
        raise ValueError("localization line budget exceeded")
    sums = torch.zeros((line_count, pretrained.report.encoder_policy.hidden_size))
    counts = torch.zeros(line_count)
    with torch.no_grad():
        for block in segment_configuration(record):
            windows = encode_block(block, pretrained.tokenizer)
            budget[1] += len(windows)
            if budget[1] > policy.max_windows:
                raise ValueError("localization window budget exceeded")
            for offset in range(0, len(windows), policy.batch_size):
                batch = windows[offset : offset + policy.batch_size]
                hidden = pretrained.model.encode(
                    torch.tensor([item.input_ids for item in batch]),
                    torch.tensor([item.attention_mask for item in batch]),
                )
                for row, window in enumerate(batch):
                    for token, lines in enumerate(window.source_lines):
                        if window.special_tokens_mask[token] or not window.attention_mask[token]:
                            continue
                        for line in lines:
                            if not 1 <= line <= line_count:
                                raise ValueError("token source line is outside configuration")
                            weight = 1 / len(lines)
                            sums[line - 1] += hidden[row, token] * weight
                            counts[line - 1] += weight
    return sums / counts.clamp_min(1e-12).unsqueeze(1), counts > 0


def _dataset_features(
    rows: list[ProbeExample],
    pretrained: TrainingResult,
    policy: LinePolicy,
) -> tuple[Tensor, Tensor, int]:
    originals = {row.parent_sha256: row.record.sanitized_text for row in rows if row.label == 0}
    vectors, labels = [], []
    excluded = 0
    budget = [0, 0]
    for row in rows:
        targets = line_targets(originals[row.parent_sha256], row.record.sanitized_text)
        if row.label and not targets.changed_lines:
            excluded += 1
            continue
        features, included = _line_features(row.record, pretrained, policy, budget)
        for line in targets.ignored_lines:
            included[line - 1] = False
        target = torch.zeros(len(included))
        for line in targets.changed_lines:
            if not included[line - 1]:
                raise ValueError("changed line has no source-aligned tokens")
            target[line - 1] = 1
        vectors.append(features[included])
        labels.append(target[included])
    x, y = torch.cat(vectors), torch.cat(labels)
    if not 0 < int(y.sum()) < len(y):
        raise ValueError("localization requires positive and negative lines in each partition")
    return x, y, excluded


def train_line_localizer(
    splits: DatasetSplitResult,
    pretrained: TrainingResult,
    mutation_types: tuple[MutationType, ...],
    *,
    policy: LinePolicy | None = None,
) -> LineResult:
    policy = LinePolicy.model_validate((policy or LinePolicy()).model_dump())
    rows, skipped = prepare_examples(splits, mutation_types, policy)
    validate_pretrained_corpus(rows, pretrained)
    pretrained = TrainingResult(
        copy.deepcopy(pretrained.model), pretrained.tokenizer, pretrained.report
    )
    pretrained.model.cpu().eval().requires_grad_(False)
    threads = torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    warn_only = torch.is_deterministic_algorithms_warn_only_enabled()
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(policy.seed)
            x, y, train_excluded = _dataset_features(rows[DatasetSplit.TRAIN], pretrained, policy)
            vx, vy, val_excluded = _dataset_features(
                rows[DatasetSplit.VALIDATION], pretrained, policy
            )
            weight = (len(y) - int(y.sum())) / int(y.sum())
            head = nn.Linear(x.shape[1], 1)
            optimizer = torch.optim.AdamW(head.parameters(), lr=policy.learning_rate)
            losses = []
            best_loss, best_epoch = float("inf"), 0
            best_weights: dict[str, Tensor] = {}
            for epoch in range(1, policy.epochs + 1):
                optimizer.zero_grad(set_to_none=True)
                loss = nn.functional.binary_cross_entropy_with_logits(
                    head(x).squeeze(1), y, pos_weight=torch.tensor(weight)
                )
                if not torch.isfinite(loss):
                    raise ValueError("non-finite localization loss")
                loss.backward()  # type: ignore[no-untyped-call]
                nn.utils.clip_grad_norm_(head.parameters(), 1, error_if_nonfinite=True)
                optimizer.step()
                with torch.no_grad():
                    val_loss = float(
                        nn.functional.binary_cross_entropy_with_logits(
                            head(vx).squeeze(1), vy, pos_weight=torch.tensor(weight)
                        )
                    )
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
                scores = head(vx).squeeze(1).sigmoid()
                metrics = _metrics(
                    torch.stack((1 - scores, scores), dim=1), vy.long(), ("unchanged", "changed")
                )
    finally:
        torch.set_num_threads(threads)
        torch.use_deterministic_algorithms(deterministic, warn_only=warn_only)
    report = LineReport(
        policy=policy,
        mutation_types=mutation_types,
        encoder_sha256=_encoder_hash(pretrained.model),
        train_fingerprint=_fingerprint(rows[DatasetSplit.TRAIN]),
        validation_fingerprint=_fingerprint(rows[DatasetSplit.VALIDATION]),
        train_lines=len(y),
        validation_lines=len(vy),
        train_positive_lines=int(y.sum()),
        validation_positive_lines=int(vy.sum()),
        positive_weight=weight,
        excluded_deletion_only={"train": train_excluded, "validation": val_excluded},
        skipped_not_applicable=skipped,
        losses=tuple(losses),
        best_epoch=best_epoch,
        validation_metrics=metrics,
    )
    return LineResult(pretrained, head, report)


def predict_lines(result: LineResult, record: ImportedDatasetRecord) -> tuple[LineScore, ...]:
    """Scores on current-file lines; requires no original text or mutation labels."""
    if result.pretrained.model.training or result.head.training:
        raise ValueError("prediction requires evaluation mode")
    features, included = _line_features(record, result.pretrained, result.report.policy, [0, 0])
    with torch.no_grad():
        scores = result.head(features).squeeze(1).sigmoid().tolist()
    return tuple(
        LineScore(
            source_sha256=record.sanitized_sha256,
            line_number=index + 1,
            changed_score=score if included[index] else None,
            predicted_changed=score > result.report.threshold if included[index] else None,
        )
        for index, score in enumerate(scores)
    )


def save_localizer(result: LineResult, path: Path) -> None:
    path.mkdir(exist_ok=False)
    save_checkpoint(result.pretrained, path / "encoder")
    text = json.dumps(
        {
            "report": result.report.model_dump(mode="json"),
            "weight": result.head.weight.detach().tolist(),
            "bias": result.head.bias.detach().tolist(),
        },
        sort_keys=True,
        allow_nan=False,
    )
    (path / "localizer.json").write_text(text, encoding="utf-8")
    (path / "localizer.sha256").write_text(digest(text), encoding="ascii")


def load_localizer(path: Path) -> LineResult:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("unsafe localizer directory")
    if {item.name for item in path.iterdir()} != {"encoder", "localizer.json", "localizer.sha256"}:
        raise ValueError("incomplete localizer bundle")
    for name in ("localizer.json", "localizer.sha256"):
        item = path / name
        if item.is_symlink() or not item.is_file() or item.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("unsafe localizer file")
    text = (path / "localizer.json").read_text(encoding="utf-8")
    if digest(text) != (path / "localizer.sha256").read_text(encoding="ascii"):
        raise ValueError("localizer checksum mismatch")
    payload = json.loads(text)
    report = LineReport.model_validate(payload["report"])
    pretrained = load_checkpoint(path / "encoder")
    if _encoder_hash(pretrained.model) != report.encoder_sha256:
        raise ValueError("localizer encoder checksum mismatch")
    with torch.random.fork_rng(devices=[]):
        head = nn.Linear(pretrained.report.encoder_policy.hidden_size, 1)
    head.load_state_dict(
        {"weight": torch.tensor(payload["weight"]), "bias": torch.tensor(payload["bias"])}
    )
    if any(not torch.isfinite(value).all() for value in head.state_dict().values()):
        raise ValueError("non-finite localizer weights")
    pretrained.model.requires_grad_(False)
    return LineResult(pretrained, head.eval(), report)
