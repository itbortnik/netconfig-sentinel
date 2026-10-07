"""Deterministic source-bound supervised adapter/head training on a frozen encoder."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

import torch
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    TypeAdapter,
    model_validator,
)
from torch import Tensor

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.evaluation.contracts import Cohort, Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.blocks import digest, segment_configuration
from ml.preprocessing.tokenization import _validate_split_entities, encode_block
from ml.training.checkpoint import load_checkpoint, save_checkpoint
from ml.training.classification import ProbeExample, _encoder_hash, validate_pretrained_corpus
from ml.training.multitask import (
    IGNORE_TARGET,
    SEVERITY_CLASSES,
    HeadPolicy,
    LossWeights,
    MultiTaskHeads,
    SupervisedTargets,
    multitask_loss,
)
from ml.training.pretraining import PretrainingResult, load_pretraining, save_pretraining
from ml.training.pretraining_data import SemanticPair
from ml.training.pretraining_transfer import (
    ObjectiveSourceBinding,
    validate_objective_model,
    validate_objective_source,
    verify_objective_binding,
)
from ml.training.transformer import ConfigEncoderMLM, TrainingResult

type PretrainedEncoder = TrainingResult | PretrainingResult


class SupervisedAnnotation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    source_sha256: Digest
    annotation_sha256: Digest
    source_review_sha256: Digest
    origin: Cohort
    target_semantics: Literal["injected_mutation", "confirmed_anomaly"]
    anomaly: StrictBool | None
    category_targets: tuple[StrictInt, ...] = Field(min_length=1, max_length=64)
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    localization_reviewed: StrictBool = False
    deletion_only: StrictBool = False
    positive_lines: tuple[StrictInt, ...] = ()
    ignored_lines: tuple[StrictInt, ...] = ()
    similarity_group: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def consistency(self) -> SupervisedAnnotation:
        if any(value not in (0, 1, IGNORE_TARGET) for value in self.category_targets):
            raise ValueError("categories require explicit 0/1 or ignored annotation")
        if (1 in self.category_targets or self.severity is not None or self.positive_lines) and (
            self.anomaly is not True
        ):
            raise ValueError(
                "positive category/severity/localization requires positive anomaly truth"
            )
        for lines in (self.positive_lines, self.ignored_lines):
            if lines != tuple(sorted(set(lines))) or any(line < 1 for line in lines):
                raise ValueError("annotation anchors must be sorted unique positive integers")
        if set(self.positive_lines) & set(self.ignored_lines):
            raise ValueError("positive lines cannot be ignored")
        if self.deletion_only and (self.positive_lines or self.anomaly is not True):
            raise ValueError(
                "deletion-only labels require positive anomaly and no current-line target"
            )
        if (
            self.positive_lines or self.ignored_lines or self.deletion_only
        ) and not self.localization_reviewed:
            raise ValueError("localization facts require an explicitly reviewed annotation")
        if self.origin == "real_confirmed" and self.target_semantics != "confirmed_anomaly":
            raise ValueError("real labels cannot be synthetic injection labels")
        return self


@dataclass(frozen=True)
class SupervisedExample:
    record: ImportedDatasetRecord
    parent_sha256: str
    annotation: SupervisedAnnotation


class FineTunePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    seed: int = Field(default=17, ge=0, le=2**31 - 1, strict=True)
    epochs: int = Field(default=20, ge=1, le=1000, strict=True)
    learning_rate: float = Field(default=0.01, gt=0, le=0.1)
    weight_decay: float = Field(default=0.01, ge=0, le=1)
    gradient_clip: float = Field(default=1, gt=0, le=100)
    max_total_windows: int = Field(default=10000, ge=1, le=100000, strict=True)
    max_feature_values: int = Field(default=4000000, ge=1024, le=16000000, strict=True)


@dataclass(frozen=True)
class AlignedFeatures:
    blocks: Tensor
    lines: Tensor
    line_numbers: tuple[int, ...]
    total_lines: int
    windows: int


class SupervisedEpoch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    epoch: int = Field(ge=1)
    train_total: float = Field(ge=0)
    validation_total: float = Field(ge=0)
    train_components: dict[str, float | None]
    validation_components: dict[str, float | None]


class _MultiTaskReportFields(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    head_policy: HeadPolicy
    training_policy: FineTunePolicy
    loss_weights: LossWeights
    encoder_sha256: Digest
    tokenizer_sha256: Digest
    train_fingerprint: Digest
    validation_fingerprint: Digest
    target_semantics: Literal["injected_mutation", "confirmed_anomaly"]
    origin_counts: dict[str, int]
    train_examples: int = Field(ge=1)
    validation_examples: int = Field(ge=1)
    trainable_parameters: int = Field(ge=1)
    parameter_count: int = Field(ge=1)
    supervised_counts: dict[str, int]
    validation_supervised_counts: dict[str, int]
    losses: tuple[SupervisedEpoch, ...]
    best_epoch: int = Field(ge=1)
    encoder_frozen: Literal[True] = True
    test_evaluated: Literal[False] = False
    production_quality_proven: Literal[False] = False
    torch_version: str

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if tuple(item.epoch for item in self.losses) != tuple(
            range(1, self.training_policy.epochs + 1)
        ):
            raise ValueError("supervised report must cover all epochs")
        if self.best_epoch != min(self.losses, key=lambda item: item.validation_total).epoch:
            raise ValueError("selected epoch must minimize validation objective")
        if self.trainable_parameters >= self.parameter_count:
            raise ValueError("frozen encoder must be included in parameter count")
        tasks = set(LossWeights.model_fields)
        for counts in (self.supervised_counts, self.validation_supervised_counts):
            if set(counts) != tasks or any(value < 0 for value in counts.values()):
                raise ValueError("supervision counts must identify all tasks")
        for name, weight in self.loss_weights.model_dump().items():
            if weight and not (
                self.supervised_counts[name] and self.validation_supervised_counts[name]
            ):
                raise ValueError("enabled objective requires train and validation supervision")
        if (
            set(self.origin_counts) - {"synthetic", "laboratory", "real_confirmed"}
            or sum(self.origin_counts.values()) != self.train_examples + self.validation_examples
            or any(count < 1 for count in self.origin_counts.values())
        ):
            raise ValueError("origin counts must cover the supervised corpus")
        for epoch in self.losses:
            for components, total in (
                (epoch.train_components, epoch.train_total),
                (epoch.validation_components, epoch.validation_total),
            ):
                if set(components) != tasks or any(
                    value is not None and value < 0 for value in components.values()
                ):
                    raise ValueError("objective components must cover the complete task catalog")
                expected = 0.0
                for name, weight in self.loss_weights.model_dump().items():
                    if weight:
                        value = components[name]
                        if value is None:
                            raise ValueError("enabled objective has no measured epoch component")
                        expected += weight * value
                if abs(expected - total) > 1e-5 * max(1, total):
                    raise ValueError("epoch totals differ from recorded objective weights")
        return self


class MultiTaskReport(_MultiTaskReportFields):
    """Legacy MLM-backed format, unchanged."""

    version: Literal["multitask-training-0.1.0"] = "multitask-training-0.1.0"


class MultiTaskTransferReport(_MultiTaskReportFields):
    """Objective-backed format with explicit source identity and reviewed label exposure."""

    version: Literal["multitask-training-0.2.0"] = "multitask-training-0.2.0"
    pretraining: ObjectiveSourceBinding


_REPORT: TypeAdapter[MultiTaskReport | MultiTaskTransferReport] = TypeAdapter(
    Annotated[MultiTaskReport | MultiTaskTransferReport, Field(discriminator="version")]
)


def _encoder_model(pretrained: PretrainedEncoder) -> ConfigEncoderMLM:
    return (
        pretrained.model.encoder if isinstance(pretrained, PretrainingResult) else pretrained.model
    )


@dataclass
class MultiTaskResult:
    pretrained: PretrainedEncoder
    heads: MultiTaskHeads
    report: MultiTaskReport | MultiTaskTransferReport


def _verified_report(result: MultiTaskResult) -> MultiTaskReport | MultiTaskTransferReport:
    report = _REPORT.validate_python(result.report.model_dump())
    if isinstance(report, MultiTaskTransferReport):
        if not isinstance(result.pretrained, PretrainingResult):
            raise ValueError("objective-backed report cannot use legacy MLM weights")
        verify_objective_binding(result.pretrained, report.pretraining)
    elif not isinstance(result.pretrained, TrainingResult):
        raise ValueError("legacy MLM report cannot use objective-backed weights")
    return report


class MultiTaskPrediction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    source_sha256: Digest
    model_sha256: Digest
    anomaly_score: float | None = Field(ge=0, le=1)
    category_scores: dict[str, float] | None
    severity_scores: dict[str, float] | None
    line_scores: tuple[float | None, ...]
    embedding: tuple[float, ...] | None
    block_attention: tuple[float, ...]
    calibrated: Literal[False] = False
    production_quality_proven: Literal[False] = False


def extract_aligned_features(
    record: ImportedDatasetRecord,
    pretrained: PretrainedEncoder,
    *,
    max_windows: int,
    max_feature_values: int = 4000000,
) -> AlignedFeatures:
    """Content-only block/line means; no role/site/vendor/identity features or truncation."""
    if pretrained.model.training:
        raise ValueError("feature extraction requires encoder evaluation mode")
    if isinstance(pretrained, PretrainingResult):
        validate_objective_model(pretrained)
        if any(module.training for module in pretrained.model.modules()):
            raise ValueError("feature extraction requires all objective modules in evaluation mode")
    record = ImportedDatasetRecord.model_validate(record.model_dump())
    total_lines = len(record.sanitized_text.splitlines())
    hidden_size = pretrained.report.encoder_policy.hidden_size
    if total_lines < 1 or (total_lines * hidden_size > max_feature_values):
        raise ValueError("aligned feature budget exceeded")
    line_sums = torch.zeros(total_lines, hidden_size)
    line_counts = torch.zeros(total_lines)
    blocks: list[Tensor] = []
    count = 0
    with torch.no_grad():
        for block in segment_configuration(record):
            windows = encode_block(block, pretrained.tokenizer)
            count += len(windows)
            if (
                count > max_windows
                or (len(blocks) + 1 + total_lines) * hidden_size > max_feature_values
            ):
                raise ValueError("aligned feature window/value budget exceeded")
            block_sum, block_count = torch.zeros(hidden_size), 0
            for window in windows:
                ids = torch.tensor([window.input_ids])
                mask = torch.tensor([window.attention_mask])
                hidden = _encoder_model(pretrained).encode(ids, mask)[0]
                for index, anchors in enumerate(window.source_lines):
                    if (
                        not anchors
                        or window.special_tokens_mask[index]
                        or not window.attention_mask[index]
                    ):
                        continue
                    block_sum += hidden[index]
                    block_count += 1
                    for line in anchors:
                        if not 1 <= line <= total_lines:
                            raise ValueError("encoder source alignment is invalid")
                        line_sums[line - 1] += hidden[index]
                        line_counts[line - 1] += 1
            if not block_count:
                raise ValueError("source block has no encoded content")
            blocks.append(block_sum / block_count)
    selected = line_counts > 0
    numbers = tuple(int(index) + 1 for index in torch.where(selected)[0])
    return AlignedFeatures(
        torch.stack(blocks),
        line_sums[selected] / line_counts[selected, None],
        numbers,
        total_lines,
        count,
    )


def _fingerprint(examples: tuple[SupervisedExample, ...]) -> str:
    return canonical_hash(
        [
            {
                "source": row.record.source_id,
                "record": row.record.record_id,
                "source_sha256": row.record.sanitized_sha256,
                "parent": row.parent_sha256,
                "annotation": row.annotation.model_dump(mode="json"),
            }
            for row in examples
        ]
    )


def _rows(
    splits: DatasetSplitResult,
    pretrained: PretrainedEncoder,
    examples: tuple[SupervisedExample, ...],
    policy: HeadPolicy,
    semantic_pairs: tuple[SemanticPair, ...] = (),
) -> dict[DatasetSplit, tuple[SupervisedExample, ...]]:
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    _validate_split_entities(splits)
    originals: dict[DatasetSplit, list[ProbeExample]] = {
        part.split: [
            ProbeExample(record, 0, None, record.sanitized_sha256) for record in part.records
        ]
        for part in splits.partitions
        if part.split is not DatasetSplit.TEST
    }
    if isinstance(pretrained, PretrainingResult):
        validate_objective_source(splits, pretrained, semantic_pairs)
    else:
        if semantic_pairs:
            raise ValueError("legacy MLM transfer cannot silently ignore semantic labels")
        validate_pretrained_corpus(originals, pretrained)
    parents = {
        (record.source_id, record.record_id): (part.split, record)
        for part in splits.partitions
        for record in part.records
    }
    grouped: dict[DatasetSplit, list[SupervisedExample]] = {
        DatasetSplit.TRAIN: [],
        DatasetSplit.VALIDATION: [],
    }
    used: dict[str, DatasetSplit] = {
        record.sanitized_sha256: DatasetSplit.TEST
        for part in splits.partitions
        if part.split is DatasetSplit.TEST
        for record in part.records
    }
    semantics = set()
    for example in examples:
        record = ImportedDatasetRecord.model_validate(example.record.model_dump())
        annotation = SupervisedAnnotation.model_validate(example.annotation.model_dump())
        parent_info = parents.get((record.source_id, record.record_id))
        if parent_info is None:
            raise ValueError("supervised example has no original split parent")
        split, parent = parent_info
        if split is DatasetSplit.TEST:
            raise ValueError("test examples cannot enter supervised training or selection")
        if parent.sanitized_sha256 != example.parent_sha256 or any(
            getattr(record, field) != getattr(parent, field)
            for field in (
                "network_id",
                "site_id",
                "device_id",
                "captured_at",
                "vendor_hint",
                "device_role",
            )
        ):
            raise ValueError("derived example does not retain its original parent membership")
        if (
            annotation.source_sha256 != record.sanitized_sha256
            or (digest(record.sanitized_text) != record.sanitized_sha256)
            or len(annotation.category_targets) != len(policy.classes)
        ):
            raise ValueError("annotation/hash/class catalog does not match the supervised input")
        if record.sanitized_sha256 in used:
            raise ValueError("duplicate or leaked supervised configuration")
        used[record.sanitized_sha256] = split
        semantics.add(annotation.target_semantics)
        grouped[split].append(SupervisedExample(record, example.parent_sha256, annotation))
        if len(grouped[split]) > policy.max_examples:
            raise ValueError("supervised full-batch example budget exceeded")
    if len(semantics) != 1 or any(not rows for rows in grouped.values()):
        raise ValueError(
            "one explicit label semantics and both train/validation partitions are required"
        )
    return {
        key: tuple(
            sorted(
                rows,
                key=lambda row: (
                    row.record.source_id,
                    row.record.record_id,
                    row.record.sanitized_sha256,
                ),
            )
        )
        for key, rows in grouped.items()
    }


def _targets(
    rows: tuple[SupervisedExample, ...], features: tuple[AlignedFeatures, ...]
) -> SupervisedTargets:
    line_targets = []
    for row, aligned in zip(rows, features, strict=True):
        annotation = row.annotation
        if any(
            line > aligned.total_lines
            for line in (*annotation.positive_lines, *annotation.ignored_lines)
        ):
            raise ValueError("localization annotation exceeds the bound current-file source")
        if not set(annotation.positive_lines).issubset(aligned.line_numbers):
            raise ValueError("positive supervised line has no aligned encoder features")
        for number in aligned.line_numbers:
            line_targets.append(
                IGNORE_TARGET
                if not annotation.localization_reviewed
                or annotation.deletion_only
                or number in annotation.ignored_lines
                else int(number in annotation.positive_lines)
            )
    return SupervisedTargets(
        anomaly=torch.tensor(
            [
                float(row.annotation.anomaly)
                if row.annotation.anomaly is not None
                else float(IGNORE_TARGET)
                for row in rows
            ]
        ),
        categories=torch.tensor(
            [row.annotation.category_targets for row in rows], dtype=torch.float32
        ),
        severity=torch.tensor(
            [
                SEVERITY_CLASSES.index(row.annotation.severity)
                if row.annotation.severity
                else IGNORE_TARGET
                for row in rows
            ]
        ),
        lines=torch.tensor(line_targets, dtype=torch.float32),
        similarity_groups=tuple(row.annotation.similarity_group for row in rows),
    )


def train_multitask(
    splits: DatasetSplitResult,
    pretrained: PretrainedEncoder,
    examples: tuple[SupervisedExample, ...],
    *,
    head_policy: HeadPolicy,
    training_policy: FineTunePolicy | None = None,
    loss_weights: LossWeights | None = None,
    semantic_pairs: tuple[SemanticPair, ...] = (),
) -> MultiTaskResult:
    """Train residual feature adapter/heads; select epoch on validation, never test labels."""
    head_policy = HeadPolicy.model_validate(head_policy.model_dump())
    policy = FineTunePolicy.model_validate((training_policy or FineTunePolicy()).model_dump())
    weights = LossWeights.model_validate((loss_weights or LossWeights()).model_dump())
    rows = _rows(splits, pretrained, examples, head_policy, semantic_pairs)
    encoder_hash = _encoder_hash(pretrained.model)
    encoder = copy.deepcopy(pretrained)
    encoder.model.eval().requires_grad_(False)
    previous_threads = torch.get_num_threads()
    deterministic, warn = (
        torch.are_deterministic_algorithms_enabled(),
        torch.is_deterministic_algorithms_warn_only_enabled(),
    )
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(policy.seed)
            features = {}
            windows, values = 0, 0
            for split, examples_for_split in rows.items():
                aligned = []
                for row in examples_for_split:
                    feature = extract_aligned_features(
                        row.record,
                        encoder,
                        max_windows=policy.max_total_windows,
                        max_feature_values=policy.max_feature_values,
                    )
                    windows += feature.windows
                    values += feature.blocks.numel() + feature.lines.numel()
                    if windows > policy.max_total_windows or values > policy.max_feature_values:
                        raise ValueError("supervised feature/window budget exceeded")
                    aligned.append(feature)
                features[split] = tuple(aligned)
            targets = {split: _targets(rows[split], feature) for split, feature in features.items()}
            heads = MultiTaskHeads(encoder.report.encoder_policy.hidden_size, head_policy)
            optimizer = torch.optim.AdamW(
                heads.parameters(), lr=policy.learning_rate, weight_decay=policy.weight_decay
            )
            losses, best, selected_epoch = [], float("inf"), 0
            selected_state = {}
            for epoch in range(1, policy.epochs + 1):
                heads.train()
                train_features = features[DatasetSplit.TRAIN]
                train_output = heads(
                    tuple(item.blocks for item in train_features),
                    tuple(item.lines for item in train_features),
                )
                train_loss = multitask_loss(train_output, targets[DatasetSplit.TRAIN], weights)
                optimizer.zero_grad(set_to_none=True)
                train_loss.total.backward()  # type: ignore[no-untyped-call]
                torch.nn.utils.clip_grad_norm_(
                    heads.parameters(), policy.gradient_clip, error_if_nonfinite=True
                )
                optimizer.step()
                heads.eval()
                validation_features = features[DatasetSplit.VALIDATION]
                with torch.no_grad():
                    validation_output = heads(
                        tuple(item.blocks for item in validation_features),
                        tuple(item.lines for item in validation_features),
                    )
                    val_loss = multitask_loss(
                        validation_output, targets[DatasetSplit.VALIDATION], weights
                    )
                val = float(val_loss.total)
                losses.append(
                    SupervisedEpoch(
                        epoch=epoch,
                        train_total=float(train_loss.total.detach()),
                        validation_total=val,
                        train_components={
                            name: float(value.detach()) if value is not None else None
                            for name, value in train_loss.components.items()
                        },
                        validation_components={
                            name: float(value) if value is not None else None
                            for name, value in val_loss.components.items()
                        },
                    )
                )
                if val < best:
                    best, selected_epoch = val, epoch
                    selected_state = {
                        name: value.detach().clone() for name, value in heads.state_dict().items()
                    }
            heads.load_state_dict(selected_state)
            heads.eval()
    finally:
        torch.use_deterministic_algorithms(deterministic, warn_only=warn)
        torch.set_num_threads(previous_threads)
    if (
        _encoder_hash(encoder.model) != encoder_hash
        or _encoder_hash(pretrained.model) != encoder_hash
    ):
        raise ValueError("supervised training changed the frozen encoder")
    report = MultiTaskReport(
        head_policy=head_policy,
        training_policy=policy,
        loss_weights=weights,
        encoder_sha256=encoder_hash,
        tokenizer_sha256=encoder.tokenizer.tokenizer_sha256,
        train_fingerprint=_fingerprint(rows[DatasetSplit.TRAIN]),
        validation_fingerprint=_fingerprint(rows[DatasetSplit.VALIDATION]),
        target_semantics=rows[DatasetSplit.TRAIN][0].annotation.target_semantics,
        origin_counts={
            origin: sum(row.annotation.origin == origin for group in rows.values() for row in group)
            for origin in sorted(
                {row.annotation.origin for group in rows.values() for row in group}
            )
        },
        train_examples=len(rows[DatasetSplit.TRAIN]),
        validation_examples=len(rows[DatasetSplit.VALIDATION]),
        trainable_parameters=sum(parameter.numel() for parameter in heads.parameters()),
        parameter_count=sum(parameter.numel() for parameter in heads.parameters())
        + encoder.report.parameter_count,
        supervised_counts=train_loss.supervised_counts,
        validation_supervised_counts=val_loss.supervised_counts,
        losses=tuple(losses),
        best_epoch=selected_epoch,
        torch_version=torch.__version__,
    )
    if isinstance(encoder, PretrainingResult):
        transfer_report = MultiTaskTransferReport(
            **report.model_dump(exclude={"version"}),
            pretraining=validate_objective_source(splits, encoder, semantic_pairs),
        )
        return MultiTaskResult(encoder, heads, transfer_report)
    return MultiTaskResult(encoder, heads, report)


def multitask_identity(result: MultiTaskResult) -> str:
    return canonical_hash(
        {
            "report": result.report.model_dump(mode="json"),
            "weights": {
                name: value.detach().cpu().tolist()
                for name, value in sorted(result.heads.state_dict().items())
            },
        }
    )


def predict_multitask(
    result: MultiTaskResult, record: ImportedDatasetRecord
) -> MultiTaskPrediction:
    if result.heads.training or result.pretrained.model.training:
        raise ValueError("prediction requires model evaluation mode")
    report = _verified_report(result)
    if (
        _encoder_hash(result.pretrained.model) != report.encoder_sha256
        or (result.pretrained.tokenizer.tokenizer_sha256 != report.tokenizer_sha256)
        or result.heads.policy != report.head_policy
    ):
        raise ValueError("supervised model/tokenizer/report binding differs")
    features = extract_aligned_features(
        record,
        result.pretrained,
        max_windows=report.training_policy.max_total_windows,
        max_feature_values=report.training_policy.max_feature_values,
    )
    with torch.no_grad():
        output = result.heads((features.blocks,), (features.lines,))
        scores: list[float | None] = [None] * features.total_lines
        if report.loss_weights.localization:
            for line, score in zip(
                features.line_numbers, output.line_logits.sigmoid().tolist(), strict=True
            ):
                scores[line - 1] = float(score)
        return MultiTaskPrediction(
            source_sha256=record.sanitized_sha256,
            model_sha256=multitask_identity(result),
            anomaly_score=float(output.anomaly_logits.sigmoid()[0])
            if report.loss_weights.anomaly
            else None,
            category_scores=dict(
                zip(
                    report.head_policy.classes,
                    output.category_logits.sigmoid()[0].tolist(),
                    strict=True,
                )
            )
            if report.loss_weights.category
            else None,
            severity_scores=dict(
                zip(
                    SEVERITY_CLASSES, output.severity_logits.softmax(dim=1)[0].tolist(), strict=True
                )
            )
            if report.loss_weights.severity
            else None,
            line_scores=tuple(scores),
            embedding=tuple(output.embeddings[0].tolist())
            if report.loss_weights.contrastive
            else None,
            block_attention=tuple(output.block_attention[0].tolist()),
        )


def save_multitask(result: MultiTaskResult, path: Path) -> None:
    report = _verified_report(result)
    if (
        report.head_policy != result.heads.policy
        or report.encoder_sha256 != _encoder_hash(result.pretrained.model)
        or (report.tokenizer_sha256 != result.pretrained.tokenizer.tokenizer_sha256)
        or any(
            not bool(torch.isfinite(value).all()) for value in result.heads.state_dict().values()
        )
    ):
        raise ValueError("supervised save requires a consistent finite model/report binding")
    path.mkdir(exist_ok=False)
    marker = path / ".incomplete"
    marker.write_text("supervised bundle writing\n", encoding="utf-8")
    if isinstance(result.pretrained, PretrainingResult):
        save_pretraining(result.pretrained, path / "encoder")
    else:
        save_checkpoint(result.pretrained, path / "encoder")
    payload = {
        "report": result.report.model_dump(mode="json"),
        "weights": {
            name: value.detach().cpu().tolist() for name, value in result.heads.state_dict().items()
        },
    }
    text = json.dumps(payload, sort_keys=True, allow_nan=False)
    (path / "heads.json").write_text(text, encoding="utf-8")
    (path / "heads.sha256").write_text(digest(text), encoding="ascii")
    marker.unlink()


def load_multitask(path: Path) -> MultiTaskResult:
    if (
        path.is_symlink()
        or not path.is_dir()
        or {item.name for item in path.iterdir()}
        != {
            "encoder",
            "heads.json",
            "heads.sha256",
        }
    ):
        raise ValueError("supervised bundle is missing, unsafe or incomplete")
    for name, limit in (("heads.json", 32 * 1024 * 1024), ("heads.sha256", 64)):
        item = path / name
        if item.is_symlink() or not item.is_file() or item.stat().st_size > limit:
            raise ValueError("unsafe supervised bundle file")
    text = (path / "heads.json").read_text(encoding="utf-8")
    if digest(text) != (path / "heads.sha256").read_text(encoding="ascii"):
        raise ValueError("supervised bundle checksum mismatch")
    from ml.evaluation.cli import _unique_pairs

    payload = json.loads(text, object_pairs_hook=_unique_pairs)
    if not isinstance(payload, dict) or set(payload) != {"report", "weights"}:
        raise ValueError("supervised bundle payload fields differ")
    report = _REPORT.validate_python(payload["report"])
    encoder: PretrainedEncoder = (
        load_pretraining(path / "encoder")
        if isinstance(report, MultiTaskTransferReport)
        else load_checkpoint(path / "encoder")
    )
    if _encoder_hash(encoder.model) != report.encoder_sha256 or (
        encoder.tokenizer.tokenizer_sha256 != report.tokenizer_sha256
    ):
        raise ValueError("supervised bundle encoder/tokenizer mismatch")
    with torch.random.fork_rng(devices=[]):
        heads = MultiTaskHeads(encoder.report.encoder_policy.hidden_size, report.head_policy)
    heads.load_state_dict(
        {name: torch.tensor(value) for name, value in payload["weights"].items()}, strict=True
    )
    if any(not bool(torch.isfinite(value).all()) for value in heads.state_dict().values()) or (
        sum(parameter.numel() for parameter in heads.parameters()) != report.trainable_parameters
        or report.parameter_count != report.trainable_parameters + encoder.report.parameter_count
    ):
        raise ValueError("supervised bundle weights or parameter counts are invalid")
    encoder.model.eval().requires_grad_(False)
    result = MultiTaskResult(encoder, heads.eval(), report)
    _verified_report(result)
    return result
