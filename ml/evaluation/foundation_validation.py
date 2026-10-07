"""Selection-only diagnostics for externally pretrained configuration feature heads."""

from __future__ import annotations

from ml.datasets import DatasetSplit, DatasetSplitResult
from ml.evaluation.contracts import EvaluationBatch, EvaluationProtocol
from ml.evaluation.metrics import canonical_hash
from ml.evaluation.multitask_validation import build_aligned_validation
from ml.evaluation.probe_validation import _identity
from ml.training.foundation_transfer import (
    FoundationTransferResult,
    foundation_transfer_identity,
    predict_foundation_transfer,
    verify_transfer,
)
from ml.training.multitask_training import (
    SupervisedExample,
    _fingerprint,
    validate_supervised_rows,
)
from ml.training.pretraining_transfer import objective_split_identity


def build_foundation_validation(
    result: FoundationTransferResult,
    splits: DatasetSplitResult,
    examples: tuple[SupervisedExample, ...],
) -> EvaluationBatch:
    report = verify_transfer(result)
    if objective_split_identity(splits) != report.source_manifest_sha256:
        raise ValueError("foundation evaluation source manifest binding differs")
    rows = validate_supervised_rows(splits, examples, report.head_policy)
    if _fingerprint(rows[DatasetSplit.TRAIN]) != report.train_fingerprint or (
        _fingerprint(rows[DatasetSplit.VALIDATION]) != report.validation_fingerprint
    ):
        raise ValueError("foundation evaluation corpus/annotation exposure differs")
    if not report.loss_weights.anomaly or not report.loss_weights.category:
        raise ValueError("foundation evaluation requires trained anomaly and category heads")
    protocol = EvaluationProtocol(
        purpose="validation_diagnostic",
        target_semantics=report.target_semantics,
        latency_scope="parsing_and_inference",
        model_version=report.version,
        model_sha256=foundation_transfer_identity(result),
        tokenizer_sha256=report.tokenizer_sha256,
        dataset_manifest_sha256=report.source_manifest_sha256,
        threshold_policy_sha256=canonical_hash("recorded-strict-0.5-supervised-head-thresholds-1"),
        classes=report.head_policy.classes,
        category_thresholds=(0.5,) * len(report.head_policy.classes),
        train=tuple(_identity(row.record, row.parent_sha256) for row in rows[DatasetSplit.TRAIN]),
        selection=tuple(
            _identity(row.record, row.parent_sha256) for row in rows[DatasetSplit.VALIDATION]
        ),
    )
    return build_aligned_validation(
        protocol,
        rows,
        lambda record: predict_foundation_transfer(result, record),
        localization_enabled=bool(report.loss_weights.localization),
    )
