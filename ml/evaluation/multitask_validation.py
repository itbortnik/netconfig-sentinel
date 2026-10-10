"""Measured joint-model validation with original corpus/annotation binding."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from time import perf_counter

import torch
from app.domain import Vendor
from app.parsers import parse_configuration

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.datasets.fixture_training import FixtureTrainingCorpus
from ml.evaluation.cli import write_report
from ml.evaluation.contracts import (
    EvaluationBatch,
    EvaluationCase,
    EvaluationProtocol,
    LineAnnotation,
)
from ml.evaluation.coverage import parser_coverage
from ml.evaluation.metrics import canonical_hash, evaluate
from ml.evaluation.probe_validation import _identity
from ml.mutation import MutationType
from ml.training.classification_smoke import classification_fixtures
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    MultiTaskFixtureTransferReport,
    MultiTaskPrediction,
    MultiTaskResult,
    MultiTaskTransferReport,
    SupervisedExample,
    _fingerprint,
    _rows,
    _verified_report,
    load_multitask,
    multitask_identity,
    predict_multitask,
)
from ml.training.pretraining import FixturePretrainingResult
from ml.training.pretraining_data import SemanticPair
from ml.training.pretraining_transfer import objective_split_identity


def build_multitask_validation(
    result: MultiTaskResult,
    splits: DatasetSplitResult,
    examples: tuple[SupervisedExample, ...],
    *,
    fixture_corpus: FixtureTrainingCorpus | None = None,
) -> EvaluationBatch:
    bound_report = _verified_report(result)
    pairs: tuple[SemanticPair, ...] = ()
    if isinstance(bound_report, (MultiTaskTransferReport, MultiTaskFixtureTransferReport)):
        if objective_split_identity(splits) != (bound_report.pretraining.source_manifest_sha256):
            raise ValueError("evaluation source manifest binding differs from transferred corpus")
        if isinstance(bound_report, MultiTaskTransferReport):
            pairs = bound_report.pretraining.semantic_pairs
    rows = _rows(
        splits,
        result.pretrained,
        examples,
        result.report.head_policy,
        pairs,
        fixture_corpus,
        bound_report.pretraining.exposure.policy
        if isinstance(bound_report, MultiTaskFixtureTransferReport)
        else None,
    )
    if isinstance(bound_report, MultiTaskFixtureTransferReport):
        from ml.training.fixture_transfer import validate_fixture_source

        if not isinstance(result.pretrained, FixturePretrainingResult):
            raise ValueError("fixture evaluation requires the bound fixture encoder")
        if (
            fixture_corpus is None
            or validate_fixture_source(
                fixture_corpus,
                result.pretrained,
                splits,
                tuple(row.record for group in rows.values() for row in group),
                policy=bound_report.pretraining.exposure.policy,
            )
            != bound_report.pretraining
        ):
            raise ValueError("fixture validation exposure differs from fitted transfer")
    if _fingerprint(rows[DatasetSplit.TRAIN]) != result.report.train_fingerprint or (
        _fingerprint(rows[DatasetSplit.VALIDATION]) != result.report.validation_fingerprint
    ):
        raise ValueError("evaluation differs from the supervised training/selection corpus")
    if not result.report.loss_weights.anomaly or not result.report.loss_weights.category:
        raise ValueError("this metric adapter requires trained anomaly and category heads")
    protocol = EvaluationProtocol(
        purpose="validation_diagnostic",
        target_semantics=result.report.target_semantics,
        latency_scope="parsing_and_inference",
        model_version=result.report.version,
        model_sha256=multitask_identity(result),
        tokenizer_sha256=result.report.tokenizer_sha256,
        dataset_manifest_sha256=objective_split_identity(splits)
        if isinstance(bound_report, (MultiTaskTransferReport, MultiTaskFixtureTransferReport))
        else canonical_hash(splits.model_dump(mode="json")),
        threshold_policy_sha256=canonical_hash("recorded-strict-0.5-supervised-head-thresholds-1"),
        classes=result.report.head_policy.classes,
        category_thresholds=(0.5,) * len(result.report.head_policy.classes),
        train=tuple(_identity(row.record, row.parent_sha256) for row in rows[DatasetSplit.TRAIN]),
        selection=tuple(
            _identity(row.record, row.parent_sha256) for row in rows[DatasetSplit.VALIDATION]
        ),
    )
    return build_aligned_validation(
        protocol,
        rows,
        lambda record: predict_multitask(result, record),
        localization_enabled=bool(result.report.loss_weights.localization),
    )


def build_aligned_validation(
    protocol: EvaluationProtocol,
    rows: dict[DatasetSplit, tuple[SupervisedExample, ...]],
    predict: Callable[[ImportedDatasetRecord], MultiTaskPrediction],
    *,
    localization_enabled: bool,
) -> EvaluationBatch:
    """Shared metric case construction; caller checks exact trained source/label exposure."""
    cases = []
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        for row in rows[DatasetSplit.VALIDATION]:
            annotation, record = row.annotation, row.record
            if annotation.anomaly is None or IGNORE_CATEGORY in annotation.category_targets:
                raise ValueError(
                    "complete anomaly/category annotations required for this metric adapter"
                )
            started = perf_counter()
            config = parse_configuration(record.sanitized_text, filename="evaluated.cfg")
            prediction = predict(record)
            elapsed = perf_counter() - started
            if prediction.category_scores is None or prediction.anomaly_score is None:
                raise ValueError("required heads are unavailable")
            lines = None
            if annotation.localization_reviewed and localization_enabled:
                ignored = set(annotation.ignored_lines)
                lines = LineAnnotation(
                    total_lines=len(prediction.line_scores),
                    ignored_lines=annotation.ignored_lines,
                    positive_lines=annotation.positive_lines,
                    deletion_only=annotation.deletion_only,
                    scored_lines=tuple(
                        index
                        for index, value in enumerate(prediction.line_scores, 1)
                        if value is not None
                        and index not in ignored
                        and not annotation.deletion_only
                    ),
                    predicted_lines=tuple(
                        index
                        for index, value in enumerate(prediction.line_scores, 1)
                        if value is not None
                        and value > 0.5
                        and index not in ignored
                        and not annotation.deletion_only
                    ),
                )
            cases.append(
                EvaluationCase(
                    case_id=canonical_hash(
                        (record.source_id, record.record_id, record.sanitized_sha256)
                    ),
                    identity=_identity(record, row.parent_sha256),
                    source_review_sha256=annotation.source_review_sha256,
                    annotation_sha256=annotation.annotation_sha256,
                    cohort=annotation.origin,
                    vendor="cisco" if record.vendor_hint is Vendor.CISCO else "juniper",
                    device_role=record.device_role,
                    anomaly_truth=annotation.anomaly,
                    category_truth=tuple(
                        label
                        for label, value in zip(
                            protocol.classes, annotation.category_targets, strict=True
                        )
                        if value == 1
                    ),
                    detection_score=prediction.anomaly_score,
                    category_scores=tuple(
                        prediction.category_scores[label] for label in protocol.classes
                    ),
                    lines=lines,
                    analysis_seconds=elapsed,
                    parser_coverage=parser_coverage(record.sanitized_text, config),
                )
            )
    finally:
        torch.set_num_threads(threads)
    return EvaluationBatch(protocol=protocol, cases=tuple(cases))


IGNORE_CATEGORY = -100


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("choose a new output directory")
    try:
        result = load_multitask(args.model)
        splits = classification_fixtures()
        examples = authored_supervision(
            splits, tuple(MutationType(label) for label in result.report.head_policy.classes)
        )
        batch = build_multitask_validation(result, splits, examples)
        report = evaluate(batch)
        args.output.mkdir(exist_ok=False)
        with (args.output / "predictions.json").open("x", encoding="utf-8") as stream:
            stream.write(batch.model_dump_json(indent=2) + "\n")
        write_report(report, args.output / "metrics.json", args.output / "reliability.svg")
    except (OSError, ValueError):
        parser.exit(
            2, "Joint model evaluation failed: check local model/corpus/annotation bindings.\n"
        )
    print(
        "Joint-model selection diagnostics written; paired views are not independent real devices."
    )


if __name__ == "__main__":
    main()
