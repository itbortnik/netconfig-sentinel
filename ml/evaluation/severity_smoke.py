"""Authored numeric severity tables for exercising offline calibration algorithms.

The 50 calibration and 50 reserved evaluation entries are numbers, not collected
configurations, devices, networks, reviewed operational annotations or model
predictions. Vendor/role labels and one grouping key per partition are hypothetical
fixture metadata. Neither identity reservation nor these labels prove physical
independence or vendor quality. No training, inference, file or network I/O occurs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from ml.evaluation.contracts import Identity
from ml.evaluation.severity_contracts import (
    SEVERITY_CLASSES,
    SeverityEvaluationBatch,
    SeverityEvaluationCase,
    SeverityEvaluationProtocol,
)

# Fixed before fitting: relative index zero is the declared target class; index
# one is its cyclic successor. Both plans include deliberately confident errors.
_CALIBRATION_CURVES = (
    (0.94, 0.02, 0.015, 0.015, 0.01),
    (0.86, 0.05, 0.04, 0.03, 0.02),
    (0.76, 0.09, 0.07, 0.05, 0.03),
    (0.64, 0.13, 0.10, 0.08, 0.05),
    (0.53, 0.18, 0.13, 0.09, 0.07),
    (0.42, 0.23, 0.17, 0.11, 0.07),
    (0.34, 0.27, 0.19, 0.13, 0.07),
    (0.25, 0.39, 0.17, 0.12, 0.07),
    (0.12, 0.68, 0.10, 0.06, 0.04),
    (0.04, 0.87, 0.04, 0.03, 0.02),
)
_EVALUATION_CURVES = (
    (0.92, 0.035, 0.02, 0.015, 0.01),
    (0.81, 0.07, 0.055, 0.04, 0.025),
    (0.70, 0.12, 0.08, 0.06, 0.04),
    (0.61, 0.17, 0.10, 0.07, 0.05),
    (0.49, 0.22, 0.14, 0.09, 0.06),
    (0.38, 0.27, 0.18, 0.11, 0.06),
    (0.30, 0.34, 0.19, 0.11, 0.06),
    (0.18, 0.52, 0.16, 0.09, 0.05),
    (0.08, 0.79, 0.06, 0.04, 0.03),
    (0.02, 0.92, 0.03, 0.02, 0.01),
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def _producer_policy() -> dict[str, object]:
    return {
        "version": "authored-numeric-severity-producer-0.1.0",
        "kind": "authored_numeric_fixture",
        "method": "fixed_relative_vectors_rotated_by_declared_class",
        "classes": SEVERITY_CLASSES,
        "calibration_curves": _CALIBRATION_CURVES,
        "reserved_evaluation_curves": _EVALUATION_CURVES,
        "trained_weights_present": False,
        "inference_performed": False,
    }


def _records(
    partition: Literal["calibration", "reserved_evaluation"],
) -> tuple[dict[str, Any], ...]:
    curves = _CALIBRATION_CURVES if partition == "calibration" else _EVALUATION_CURVES
    result = []
    for class_index, label in enumerate(SEVERITY_CLASSES):
        for index, relative in enumerate(curves):
            result.append(
                {
                    "version": "authored-severity-numeric-record-0.1.0",
                    "kind": "numeric_table_entry",
                    "partition": partition,
                    "index_within_class": index,
                    "declared_severity": label,
                    "probabilities": tuple(
                        relative[(column - class_index) % 5] for column in range(5)
                    ),
                    "hypothetical_vendor": "cisco" if index % 2 == 0 else "juniper",
                    "hypothetical_role": "hypothetical-edge"
                    if index % 2 == 0
                    else "hypothetical-core",
                }
            )
    return tuple(result)


def _annotation(record: dict[str, Any]) -> dict[str, object]:
    return {
        "version": "authored-severity-numeric-annotation-0.1.0",
        "source_sha256": _sha(record),
        "semantics": "declared_numeric_target_only",
        "anomaly_truth": True,
        "severity_truth": record["declared_severity"],
        "operational_human_annotation_present": False,
    }


def _case(record: dict[str, Any], producer_sha256: str) -> SeverityEvaluationCase:
    source = _sha(record)
    partition = record["partition"]
    grouping = {
        field: _sha(
            {"kind": "hypothetical_numeric_group", "partition": partition, "dimension": field}
        )
        for field in ("family_key", "device_key", "site_key", "network_key")
    }
    return SeverityEvaluationCase(
        case_id=_sha({"kind": "authored_numeric_case", "source_sha256": source}),
        identity=Identity(source_sha256=source, **grouping),
        source_review_sha256=_sha(
            {
                "version": "authored-numeric-source-declaration-0.1.0",
                "source_sha256": source,
                "declaration": "locally_authored_numbers_no_configuration_or_external_source",
                "operational_source_review_present": False,
            }
        ),
        annotation_sha256=_sha(_annotation(record)),
        prediction_sha256=_sha(
            {
                "version": "authored-numeric-score-record-0.1.0",
                "producer_sha256": producer_sha256,
                "source_sha256": source,
                "classes": SEVERITY_CLASSES,
                "probabilities": record["probabilities"],
                "inference_performed": False,
            }
        ),
        cohort="synthetic",
        vendor=record["hypothetical_vendor"],
        device_role=record["hypothetical_role"],
        anomaly_truth=True,
        severity_truth=record["declared_severity"],
        probabilities=record["probabilities"],
    )


def authored_numeric_severity_batches() -> tuple[SeverityEvaluationBatch, SeverityEvaluationBatch]:
    """Return fresh calibration and reserved evaluation tables with real numeric hashes.

    ``model_sha256`` identifies the declared numeric producer policy, not a model
    checkpoint. Source, review, annotation and prediction hashes identify the exact
    numeric records/declarations above. Manifest hashes bind both fixed tables;
    the calibration protocol carries only reserved identities, never reserved rows.
    """
    calibration_records, evaluation_records = (
        _records("calibration"),
        _records("reserved_evaluation"),
    )
    producer = _sha(_producer_policy())
    fitting = tuple(_case(record, producer) for record in calibration_records)
    evaluation = tuple(_case(record, producer) for record in evaluation_records)
    common = {
        "target_semantics": "authored_severity_fixture",
        "score_provenance": "authored_numeric_fixture",
        "model_version": "authored-numeric-severity-producer-0.1.0",
        "model_sha256": producer,
        "tokenizer_sha256": None,
        "training_report_sha256": None,
        "dataset_manifest_sha256": _sha(
            {
                "version": "authored-severity-numeric-manifest-0.1.0",
                "kind": "numbers_not_configuration_corpus",
                "producer_policy": _producer_policy(),
                "calibration_records": calibration_records,
                "reserved_evaluation_records": evaluation_records,
            }
        ),
        "annotation_manifest_sha256": _sha(
            {
                "version": "authored-severity-numeric-annotations-0.1.0",
                "annotations": tuple(
                    _annotation(record) for record in (*calibration_records, *evaluation_records)
                ),
                "operational_human_annotations_present": False,
            }
        ),
        "threshold_policy_sha256": _sha(
            {
                "version": "fixed-severity-thresholds-0.1.0",
                "classes": SEVERITY_CLASSES,
                "thresholds": (0.5,) * 5,
                "comparison": "strictly_greater",
            }
        ),
        "train": (),
        "selection": (),
        "reserved_test": tuple(case.identity for case in evaluation),
    }
    return (
        SeverityEvaluationBatch(
            protocol=SeverityEvaluationProtocol.model_validate(
                {**common, "purpose": "validation_diagnostic"}
            ),
            cases=fitting,
        ),
        SeverityEvaluationBatch(
            protocol=SeverityEvaluationProtocol.model_validate(
                {**common, "purpose": "independent_test"}
            ),
            cases=evaluation,
        ),
    )
