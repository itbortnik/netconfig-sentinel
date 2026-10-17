"""Retained native/foundation severity predictions, without loading or executing weights.

This checks supplied report/source/annotation/prediction and exposure bindings.
It does not authenticate inference, model weights, annotation truth or source rights.
Raw retained sources stay within this explicitly called private adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.domain import Vendor

from ml.evaluation.metrics import canonical_hash
from ml.evaluation.severity import evaluate_severity
from ml.evaluation.severity_contracts import (
    SEVERITY_CLASSES,
    SeverityEvaluationBatch,
    SeverityEvaluationCase,
    SeverityEvaluationProtocol,
)

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferReport
    from ml.training.multitask_training import MultiTaskPrediction, Report, SupervisedExample


@dataclass(frozen=True)
class RetainedSeverityPrediction:
    example: SupervisedExample = field(repr=False)
    prediction: MultiTaskPrediction = field(repr=False)


def build_retained_severity_batch(
    protocol: SeverityEvaluationProtocol,
    *,
    training_report: Report | FoundationTransferReport,
    train: tuple[SupervisedExample, ...],
    selection: tuple[SupervisedExample, ...],
    rows: tuple[RetainedSeverityPrediction, ...],
) -> SeverityEvaluationBatch:
    """No silent filtering; a disabled/unknown/unbound row refuses the entire batch.

    Caller retains the global dataset/annotation manifests identified by protocol.
    Exact supplied training/selection rows must reproduce the saved report; the
    model SHA on retained predictions remains a declaration, not weight authentication.
    """
    try:
        protocol = SeverityEvaluationProtocol.model_validate(protocol.model_dump(warnings=False))
        if protocol.score_provenance != "trained_severity_head" or (
            protocol.calibration_sha256 is not None
            or not 1 <= len(rows) <= 20000
            or len(train) > 20000
            or len(selection) > 20000
        ):
            raise ValueError("invalid retained severity selection")

        # Optional training dependencies are imported only for this explicit adapter.
        from ml.datasets import ImportedDatasetRecord
        from ml.evaluation.probe_validation import _identity
        from ml.preprocessing.blocks import digest
        from ml.training.foundation_transfer import FoundationTransferReport
        from ml.training.multitask_training import (
            _REPORT,
            MultiTaskPrediction,
            SupervisedAnnotation,
            SupervisedExample,
            _fingerprint,
        )

        report = (
            FoundationTransferReport.model_validate(training_report.model_dump(warnings=False))
            if isinstance(training_report, FoundationTransferReport)
            else _REPORT.validate_python(training_report.model_dump(warnings=False))
        )
        if not report.loss_weights.severity or (
            protocol.model_version != report.version
            or protocol.tokenizer_sha256 != report.tokenizer_sha256
            or protocol.training_report_sha256 != canonical_hash(report.model_dump(mode="json"))
            or protocol.target_semantics != report.target_semantics
            or len(train) != report.train_examples
            or len(selection) != report.validation_examples
        ):
            raise ValueError("severity training report differs")

        text_bytes = 0

        def checked_example(example: SupervisedExample) -> SupervisedExample:
            nonlocal text_bytes
            record = ImportedDatasetRecord.model_validate(example.record.model_dump(warnings=False))
            annotation = SupervisedAnnotation.model_validate(
                example.annotation.model_dump(warnings=False)
            )
            text_bytes += len(record.sanitized_text.encode("utf-8"))
            if (
                text_bytes > 64 * 1024 * 1024
                or len(record.sanitized_text.splitlines()) > 10000
                or digest(record.sanitized_text) != record.sanitized_sha256
                or annotation.source_sha256 != record.sanitized_sha256
                or annotation.target_semantics != report.target_semantics
                or len(annotation.category_targets) != len(report.head_policy.classes)
                or record.vendor_hint not in (Vendor.CISCO, Vendor.JUNIPER)
                or record.captured_at.tzinfo is None
                or record.captured_at.utcoffset() is None
                or any(
                    not value.strip() or len(value) > 512
                    for value in (
                        record.source_id,
                        record.record_id,
                        record.device_id,
                        record.site_id,
                        record.network_id,
                    )
                )
            ):
                raise ValueError("retained severity source differs")
            # Reuse the old identity semantics and validate the supplied family hash.
            _identity(record, example.parent_sha256)
            return SupervisedExample(record, example.parent_sha256, annotation)

        train = tuple(checked_example(example) for example in train)
        selection = tuple(checked_example(example) for example in selection)
        if _fingerprint(train) != report.train_fingerprint or (
            _fingerprint(selection) != report.validation_fingerprint
        ):
            raise ValueError("retained severity training annotation exposure differs")
        for examples, counts in (
            (train, report.supervised_counts),
            (selection, report.validation_supervised_counts),
        ):
            support = sum(example.annotation.severity is not None for example in examples)
            if support < 1 or support != counts["severity"]:
                raise ValueError("retained severity supervision differs from the training report")
        for examples, declared in ((train, protocol.train), (selection, protocol.selection)):
            actual = tuple(_identity(example.record, example.parent_sha256) for example in examples)
            if sorted(canonical_hash(item.model_dump(mode="json")) for item in actual) != sorted(
                canonical_hash(item.model_dump(mode="json")) for item in declared
            ):
                raise ValueError("retained severity entity exposure differs")

        cases = []
        for row in rows:
            example = checked_example(row.example)
            raw_scores = row.prediction.severity_scores
            if (
                not isinstance(raw_scores, dict)
                or set(raw_scores) != set(SEVERITY_CLASSES)
                or row.prediction.calibrated is not False
            ):
                raise ValueError("retained severity head is unavailable")
            prediction = MultiTaskPrediction.model_validate(
                row.prediction.model_dump(warnings=False)
            )
            if (
                example.annotation.anomaly is not True
                or example.annotation.severity is None
                or prediction.severity_scores is None
                or set(prediction.severity_scores) != set(SEVERITY_CLASSES)
                or prediction.source_sha256 != example.record.sanitized_sha256
                or prediction.model_sha256 != protocol.model_sha256
                or prediction.calibrated is not False
                or len(prediction.line_scores) != len(example.record.sanitized_text.splitlines())
            ):
                raise ValueError("retained severity prediction differs")
            cases.append(
                SeverityEvaluationCase(
                    case_id=canonical_hash(
                        (
                            example.record.source_id,
                            example.record.record_id,
                            example.record.sanitized_sha256,
                        )
                    ),
                    identity=_identity(example.record, example.parent_sha256),
                    source_review_sha256=example.annotation.source_review_sha256,
                    annotation_sha256=example.annotation.annotation_sha256,
                    prediction_sha256=canonical_hash(prediction.model_dump(mode="json")),
                    cohort=example.annotation.origin,
                    vendor="cisco" if example.record.vendor_hint is Vendor.CISCO else "juniper",
                    device_role=example.record.device_role,
                    anomaly_truth=True,
                    severity_truth=example.annotation.severity,
                    # Validate original values before old permissive float coercion.
                    probabilities=tuple(raw_scores[label] for label in SEVERITY_CLASSES),
                )
            )
        batch = SeverityEvaluationBatch(protocol=protocol, cases=tuple(cases))
        evaluate_severity(batch)  # Exact reservation or diagnostic exclusion gates also apply.
        return batch
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ValueError("Retained severity prediction binding is unavailable.") from None
