"""Parameter-efficient configuration training against a pinned external frozen source."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import torch
from pydantic import model_validator

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.blocks import digest
from ml.training.foundation import ConfigFoundation, FoundationIdentity
from ml.training.multitask import HeadPolicy, LossWeights, MultiTaskHeads
from ml.training.multitask_training import (
    AlignedFeatures,
    FineTunePolicy,
    MultiTaskPrediction,
    SupervisedExample,
    _fingerprint,
    _MultiTaskReportFields,
    fit_aligned_heads,
    prediction_from_aligned_features,
    validate_supervised_rows,
)
from ml.training.pretraining_transfer import objective_split_identity


class FoundationTransferReport(_MultiTaskReportFields):
    version: Literal["foundation-config-transfer-0.1.0"] = "foundation-config-transfer-0.1.0"
    foundation: FoundationIdentity
    source_manifest_sha256: Digest
    adaptation: Literal["frozen-token-features-residual-adapter-heads"] = (
        "frozen-token-features-residual-adapter-heads"
    )
    external_pretraining_isolation_proven: Literal[False] = False
    attention_lora: Literal[False] = False

    @model_validator(mode="after")
    def binding(self) -> FoundationTransferReport:
        if (
            self.encoder_sha256 != self.foundation.weights_sha256
            or self.tokenizer_sha256 != self.foundation.tokenizer_sha256
            or self.parameter_count != self.trainable_parameters + self.foundation.parameter_count
        ):
            raise ValueError("foundation transfer report source binding differs")
        return self


@dataclass(frozen=True)
class FoundationTransferResult:
    source: ConfigFoundation
    heads: MultiTaskHeads
    report: FoundationTransferReport


def verify_transfer(result: FoundationTransferResult) -> FoundationTransferReport:
    report = FoundationTransferReport.model_validate(result.report.model_dump())
    if result.source.verify() != report.foundation or result.heads.policy != report.head_policy:
        raise ValueError("foundation transfer model/report binding differs")
    if any(module.training for module in result.heads.modules()) or any(
        parameter.grad is not None for parameter in result.heads.parameters()
    ):
        raise ValueError("foundation transfer inference requires clean evaluation state")
    if sum(parameter.numel() for parameter in result.heads.parameters()) != (
        report.trainable_parameters
    ) or any(
        tensor.device.type != "cpu"
        or tensor.dtype != torch.float32
        or not bool(torch.isfinite(tensor).all())
        for tensor in result.heads.state_dict().values()
    ):
        raise ValueError("foundation transfer head parameters differ or are not finite CPU tensors")
    return report


def train_foundation_transfer(
    splits: DatasetSplitResult,
    source: ConfigFoundation,
    examples: tuple[SupervisedExample, ...],
    *,
    head_policy: HeadPolicy,
    training_policy: FineTunePolicy | None = None,
    loss_weights: LossWeights | None = None,
) -> FoundationTransferResult:
    """Fit only feature adapter/pooling/heads; local test is never fit or selected."""
    identity = source.verify()
    head_policy = HeadPolicy.model_validate(head_policy.model_dump())
    policy = FineTunePolicy.model_validate((training_policy or FineTunePolicy()).model_dump())
    weights = LossWeights.model_validate((loss_weights or LossWeights()).model_dump())
    rows = validate_supervised_rows(splits, examples, head_policy)
    threads = torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    warn = torch.is_deterministic_algorithms_warn_only_enabled()
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(policy.seed)
            features: dict[DatasetSplit, tuple[AlignedFeatures, ...]] = {}
            windows, values = 0, 0
            for split, group in rows.items():
                aligned = []
                for row in group:
                    feature = source.features(
                        row.record,
                        max_windows=policy.max_total_windows,
                        max_feature_values=policy.max_feature_values,
                    )
                    windows += feature.windows
                    values += feature.blocks.numel() + feature.lines.numel()
                    if windows > policy.max_total_windows or values > policy.max_feature_values:
                        raise ValueError("foundation transfer feature/window budget exceeded")
                    aligned.append(feature)
                features[split] = tuple(aligned)
            fitted = fit_aligned_heads(
                rows, features, identity.hidden_size, head_policy, policy, weights
            )
    finally:
        torch.use_deterministic_algorithms(deterministic, warn_only=warn)
        torch.set_num_threads(threads)
    if source.verify() != identity:
        raise ValueError("foundation transfer changed its frozen source")
    # Gradients are training state, not retained or used during inference/save.
    fitted.heads.zero_grad(set_to_none=True)
    trainable = sum(parameter.numel() for parameter in fitted.heads.parameters())
    report = FoundationTransferReport(
        head_policy=head_policy,
        training_policy=policy,
        loss_weights=weights,
        encoder_sha256=identity.weights_sha256,
        tokenizer_sha256=identity.tokenizer_sha256,
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
        trainable_parameters=trainable,
        parameter_count=trainable + identity.parameter_count,
        supervised_counts=fitted.supervised_counts,
        validation_supervised_counts=fitted.validation_supervised_counts,
        losses=fitted.losses,
        best_epoch=fitted.best_epoch,
        torch_version=torch.__version__,
        foundation=identity,
        source_manifest_sha256=objective_split_identity(splits),
    )
    return FoundationTransferResult(source, fitted.heads, report)


def _payload(result: FoundationTransferResult) -> dict[str, object]:
    return {
        "report": result.report.model_dump(mode="json"),
        "weights": {
            name: tensor.detach().cpu().tolist()
            for name, tensor in sorted(result.heads.state_dict().items())
        },
    }


def foundation_transfer_identity(result: FoundationTransferResult) -> str:
    return canonical_hash(_payload(result))


def predict_foundation_transfer(
    result: FoundationTransferResult, record: ImportedDatasetRecord
) -> MultiTaskPrediction:
    report = verify_transfer(result)
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        features = result.source.features(
            record,
            max_windows=report.training_policy.max_total_windows,
            max_feature_values=report.training_policy.max_feature_values,
        )
        prediction = prediction_from_aligned_features(
            result.heads,
            features,
            report.loss_weights,
            record.sanitized_sha256,
            foundation_transfer_identity(result),
        )
    finally:
        torch.set_num_threads(threads)
    verify_transfer(result)
    return prediction


def _safe_path(path: Path) -> None:
    if any(item.is_symlink() or item.is_junction() for item in (path, *path.parents)):
        raise ValueError("foundation transfer path has a linked component")


def save_foundation_transfer(result: FoundationTransferResult, path: Path) -> str:
    """New-only head/report bundle; external weights stay at the explicit operator source."""
    verify_transfer(result)
    _safe_path(path)
    payload = _payload(result)
    text = json.dumps(payload, sort_keys=True, allow_nan=False)
    if len(text.encode("utf-8")) > 32 * 1024 * 1024:
        raise ValueError("foundation transfer bundle exceeds budget")
    path.mkdir(exist_ok=False)
    marker = path / ".incomplete"
    with marker.open("x", encoding="utf-8") as stream:
        stream.write("foundation transfer bundle writing\n")
    for name, content in (("heads.json", text), ("heads.sha256", digest(text))):
        with (path / name).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    marker.unlink()
    return canonical_hash(payload)


def load_foundation_transfer(
    path: Path, *, source_root: Path, expected_identity: str
) -> FoundationTransferResult:
    """Verify independent full-model pin before decoding heads or allocating the source."""
    _safe_path(path)
    if not path.is_dir() or {item.name for item in path.iterdir()} != {
        "heads.json",
        "heads.sha256",
    }:
        raise ValueError("foundation transfer inventory is unsafe or incomplete")
    contents = {}
    for name, limit in (("heads.json", 32 * 1024 * 1024), ("heads.sha256", 64)):
        item = path / name
        _safe_path(item)
        if not item.is_file() or item.stat().st_size > limit:
            raise ValueError("foundation transfer file is unsafe or exceeds budget")
        with item.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("foundation transfer file exceeds budget")
        contents[name] = raw.decode("utf-8")
    if digest(contents["heads.json"]) != contents["heads.sha256"]:
        raise ValueError("foundation transfer checksum differs")
    from ml.evaluation.cli import _unique_pairs

    payload = json.loads(contents["heads.json"], object_pairs_hook=_unique_pairs)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"report", "weights"}
        or (canonical_hash(payload) != expected_identity)
    ):
        raise ValueError("foundation transfer independent identity pin differs")
    report = FoundationTransferReport.model_validate(payload["report"])
    source = ConfigFoundation(source_root)
    if source.verify() != report.foundation:
        raise ValueError("foundation transfer external source/runtime differs")
    with torch.random.fork_rng(devices=[]):
        heads = MultiTaskHeads(report.foundation.hidden_size, report.head_policy)
    heads.load_state_dict(
        {name: torch.tensor(values) for name, values in payload["weights"].items()}, strict=True
    )
    result = FoundationTransferResult(source, heads.eval(), report)
    verify_transfer(result)
    return result
