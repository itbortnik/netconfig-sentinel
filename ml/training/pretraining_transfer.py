"""Explicit objective-pretraining provenance, never relabeled as a legacy MLM run."""

from __future__ import annotations

from typing import Literal

import torch
from pydantic import BaseModel, ConfigDict, Field, model_validator
from torch import nn

from ml.datasets import DatasetSplit, DatasetSplitResult
from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.tokenization import TokenizerArtifact
from ml.training.pretraining import (
    FixturePretrainingReport,
    FixturePretrainingResult,
    PretrainingReport,
    PretrainingResult,
    pretraining_identity,
)
from ml.training.pretraining_data import SemanticPair, prepare_pretraining


class ObjectiveSourceBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["objective-source-binding-0.1.0"] = "objective-source-binding-0.1.0"
    pretraining_sha256: Digest
    report_sha256: Digest
    source_manifest_sha256: Digest
    semantic_pairs_sha256: Digest
    semantic_pairs: tuple[SemanticPair, ...] = Field(max_length=2048)
    external_foundation_model: Literal[False] = False
    test_targets_used: Literal[False] = False

    @model_validator(mode="after")
    def labels_bound(self) -> ObjectiveSourceBinding:
        if self.semantic_pairs_sha256 != canonical_hash(
            [pair.model_dump(mode="json") for pair in self.semantic_pairs]
        ):
            raise ValueError("semantic label binding differs")
        keys = [
            tuple(sorted((pair.left_sha256, pair.right_sha256))) for pair in self.semantic_pairs
        ]
        if len(keys) != len(set(keys)) or len({pair.scope for pair in self.semantic_pairs}) > 1:
            raise ValueError("semantic label binding contains duplicates or mixed scopes")
        return self


def objective_split_identity(splits: DatasetSplitResult) -> str:
    """Bind the full split artifact, sorting only the model's explicitly unordered set."""
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    payload = splits.model_dump(mode="json")
    for audit in payload["template_audit"]:
        audit["splits"] = sorted(audit["splits"])
    return canonical_hash(payload)


def validate_objective_model(source: PretrainingResult) -> None:
    """Validate in-memory copies too, before feature extraction or bundle creation."""
    report = PretrainingReport.model_validate(source.report.model_dump())
    _validate_encoder_model(source, report)


def validate_fixture_model(source: FixturePretrainingResult) -> None:
    report = FixturePretrainingReport.model_validate(source.report.model_dump())
    _validate_encoder_model(source, report)


def _validate_encoder_model(
    source: PretrainingResult | FixturePretrainingResult,
    report: PretrainingReport | FixturePretrainingReport,
) -> None:
    tokenizer = TokenizerArtifact.model_validate(source.tokenizer.model_dump())
    model = source.model
    encoder = model.encoder
    if (
        report.tokenizer_sha256 != tokenizer.tokenizer_sha256
        or report.train_source_fingerprint != tokenizer.training_fingerprint
        or report.encoder_policy != model.encoder_policy
        or report.training_policy != model.training_policy
        or report.parameter_count != sum(parameter.numel() for parameter in model.parameters())
        or len(encoder.layers) != report.encoder_policy.layers
        or encoder.tokens.num_embeddings != tokenizer.actual_vocab_size
        or encoder.positions.num_embeddings != tokenizer.policy.context_length
        or encoder.tokens.embedding_dim != report.encoder_policy.hidden_size
        or any(
            not isinstance(layer, nn.TransformerEncoderLayer)
            or layer.self_attn.num_heads != report.encoder_policy.heads
            or layer.linear1.out_features != report.encoder_policy.feedforward_size
            for layer in encoder.layers
        )
        or any(
            value.device.type != "cpu"
            or value.dtype != torch.float32
            or not bool(torch.isfinite(value).all())
            for value in model.state_dict().values()
        )
    ):
        raise ValueError("objective model/report/tokenizer binding differs or is not finite CPU")
    if isinstance(report, FixturePretrainingReport) and (
        report.corpus.training_count != tokenizer.training_record_count
        or report.corpus.block_count != tokenizer.training_block_count
    ):
        raise ValueError("fixture source tokenizer/exposure counts differ")


def verify_objective_binding(source: PretrainingResult, binding: ObjectiveSourceBinding) -> None:
    binding = ObjectiveSourceBinding.model_validate(binding.model_dump())
    validate_objective_model(source)
    if (
        pretraining_identity(source) != binding.pretraining_sha256
        or canonical_hash(source.report.model_dump(mode="json")) != binding.report_sha256
        or source.report.semantic_scopes
        != tuple(sorted({pair.scope for pair in binding.semantic_pairs}))
        or source.report.semantic_origin_counts
        != {
            origin: sum(pair.origin == origin for pair in binding.semantic_pairs)
            for origin in sorted({pair.origin for pair in binding.semantic_pairs})
        }
    ):
        raise ValueError("objective pretraining provenance binding differs")


def validate_objective_source(
    splits: DatasetSplitResult,
    source: PretrainingResult,
    semantic_pairs: tuple[SemanticPair, ...],
) -> ObjectiveSourceBinding:
    """Regenerate exact partition-local targets; no weight update or test targets."""
    validate_objective_model(source)
    report, policy = source.report, source.report.training_policy
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    semantic_pairs = tuple(
        SemanticPair.model_validate(pair.model_dump()) for pair in semantic_pairs
    )
    data = prepare_pretraining(
        splits,
        source.tokenizer,
        seed=policy.seed,
        semantic_pairs=semantic_pairs,
        max_records=policy.max_records,
        max_windows=policy.max_windows,
        max_examples=policy.max_examples,
    )
    train, validation = data[DatasetSplit.TRAIN], data[DatasetSplit.VALIDATION]
    if (
        train.source_fingerprint != report.train_source_fingerprint
        or validation.source_fingerprint != report.validation_source_fingerprint
        or train.fingerprint != report.train_fingerprint
        or validation.fingerprint != report.validation_fingerprint
        or {"train": train.records, "validation": validation.records} != report.source_counts
        or train.counts() != report.train_counts
        or validation.counts() != report.validation_counts
        or train.semantic_scopes != report.semantic_scopes
    ):
        raise ValueError("objective pretraining corpus/target exposure binding differs")
    binding = ObjectiveSourceBinding(
        pretraining_sha256=pretraining_identity(source),
        report_sha256=canonical_hash(report.model_dump(mode="json")),
        source_manifest_sha256=objective_split_identity(splits),
        semantic_pairs_sha256=canonical_hash(
            [pair.model_dump(mode="json") for pair in semantic_pairs]
        ),
        semantic_pairs=semantic_pairs,
    )
    verify_objective_binding(source, binding)
    return binding
