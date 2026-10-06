"""Measured synthetic validation adapter for existing frozen classifier/localizer bundles."""

from __future__ import annotations

import argparse
from pathlib import Path
from time import perf_counter

import torch
from app.domain import Vendor
from app.parsers import parse_configuration

from ml.datasets import DatasetSplit, ImportedDatasetRecord
from ml.evaluation.cli import write_report
from ml.evaluation.contracts import (
    EvaluationBatch,
    EvaluationCase,
    EvaluationProtocol,
    Identity,
    LineAnnotation,
)
from ml.evaluation.coverage import parser_coverage
from ml.evaluation.metrics import canonical_hash, evaluate
from ml.mutation import MutationType
from ml.training.classification import (
    REFERENCE_CLASS,
    ProbeReport,
    ProbeResult,
    _encoder_hash,
    _fingerprint,
    load_probe,
    predict_mutations,
    prepare_examples,
    validate_pretrained_corpus,
)
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import (
    LineResult,
    line_targets,
    load_localizer,
    localizer_identity,
    predict_lines,
)


def _identity(record: ImportedDatasetRecord, parent: str) -> Identity:
    return Identity(
        source_sha256=record.sanitized_sha256,
        family_key=parent,
        device_key=canonical_hash((record.source_id, record.device_id)),
        site_key=canonical_hash((record.source_id, record.site_id)),
        network_key=canonical_hash((record.source_id, record.network_id)),
    )


def build_probe_validation(
    result: ProbeResult,
    *,
    localizer: LineResult | None = None,
) -> EvaluationBatch:
    """Known authored fixture only: injected mutation is not a real anomaly/healthy label."""
    report = ProbeReport.model_validate(result.report.model_dump())
    splits = classification_fixtures()
    types = tuple(MutationType(name) for name in report.classes[1:])
    rows, _ = prepare_examples(splits, types, report.policy)
    validate_pretrained_corpus(rows, result.pretrained)
    if _encoder_hash(result.pretrained.model) != report.encoder_sha256 or (
        _fingerprint(rows[DatasetSplit.TRAIN]) != report.train_fingerprint
        or _fingerprint(rows[DatasetSplit.VALIDATION]) != report.validation_fingerprint
    ):
        raise ValueError("probe does not match the recorded authored validation corpus")
    if localizer is not None and (
        localizer.report.encoder_sha256 != report.encoder_sha256
        or localizer.report.train_fingerprint != report.train_fingerprint
        or localizer.report.validation_fingerprint != report.validation_fingerprint
        or localizer.report.mutation_types != types
    ):
        raise ValueError("localizer differs from the classifier encoder/corpus/classes")
    model_hash = canonical_hash(
        {
            "encoder": report.encoder_sha256,
            "report": report.model_dump(mode="json"),
            "head": {
                name: value.detach().cpu().tolist()
                for name, value in sorted(result.head.state_dict().items())
            },
            "localizer": localizer_identity(localizer) if localizer else None,
        }
    )
    protocol = EvaluationProtocol(
        purpose="validation_diagnostic",
        target_semantics="injected_mutation",
        latency_scope="parsing_and_inference",
        model_version=report.version,
        model_sha256=model_hash,
        tokenizer_sha256=result.pretrained.tokenizer.tokenizer_sha256,
        dataset_manifest_sha256=canonical_hash(splits.model_dump(mode="json")),
        threshold_policy_sha256=canonical_hash(
            {
                "detection": 0.5,
                "categories": 0.5,
                "line": localizer.report.threshold if localizer else None,
            }
        ),
        classes=report.classes[1:],
        category_thresholds=(0.5,) * len(types),
        train=tuple(_identity(row.record, row.parent_sha256) for row in rows[DatasetSplit.TRAIN]),
        selection=tuple(
            _identity(row.record, row.parent_sha256) for row in rows[DatasetSplit.VALIDATION]
        ),
    )
    validation = rows[DatasetSplit.VALIDATION]
    parents = {row.parent_sha256: row.record.sanitized_text for row in validation if row.label == 0}
    cases = []
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        for row in validation:
            record = row.record
            started = perf_counter()
            config = parse_configuration(record.sanitized_text, filename="synthetic.cfg")
            scores = predict_mutations(result, record)
            lines = None
            if localizer is not None:
                targets = line_targets(parents[row.parent_sha256], record.sanitized_text)
                deletion = bool(row.label and not targets.changed_lines)
                predictions = () if deletion else predict_lines(localizer, record)
                ignored = set(targets.ignored_lines)
                lines = LineAnnotation(
                    total_lines=len(record.sanitized_text.splitlines()),
                    ignored_lines=tuple(sorted(ignored)),
                    positive_lines=targets.changed_lines,
                    scored_lines=tuple(
                        item.line_number
                        for item in predictions
                        if item.changed_score is not None and item.line_number not in ignored
                    ),
                    predicted_lines=tuple(
                        item.line_number
                        for item in predictions
                        if item.changed_score is not None
                        and item.changed_score > localizer.report.threshold
                        and item.line_number not in ignored
                    ),
                    deletion_only=deletion,
                )
            elapsed = perf_counter() - started
            cases.append(
                EvaluationCase(
                    case_id=canonical_hash(
                        (record.source_id, record.record_id, record.sanitized_sha256, row.label)
                    ),
                    identity=_identity(record, row.parent_sha256),
                    source_review_sha256=canonical_hash(
                        "owned classification fixture source-0.1.0"
                    ),
                    annotation_sha256=canonical_hash(
                        (row.mutation_id, row.parent_sha256, row.label)
                    ),
                    cohort="synthetic",
                    vendor="cisco" if record.vendor_hint is Vendor.CISCO else "juniper",
                    device_role=record.device_role,
                    anomaly_truth=bool(row.label),
                    category_truth=(report.classes[row.label],) if row.label else (),
                    detection_score=1 - scores[REFERENCE_CLASS],
                    category_scores=tuple(scores[label] for label in protocol.classes),
                    lines=lines,
                    analysis_seconds=elapsed,
                    parser_coverage=parser_coverage(record.sanitized_text, config),
                )
            )
    finally:
        torch.set_num_threads(threads)
    return EvaluationBatch(protocol=protocol, cases=tuple(cases))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--localizer", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must be a new local directory")
    try:
        batch = build_probe_validation(
            load_probe(args.probe),
            localizer=load_localizer(args.localizer) if args.localizer else None,
        )
        report = evaluate(batch)
        args.output.mkdir(exist_ok=False)
        with (args.output / "predictions.json").open("x", encoding="utf-8") as stream:
            stream.write(batch.model_dump_json(indent=2) + "\n")
        write_report(report, args.output / "metrics.json", args.output / "reliability.svg")
    except (OSError, ValueError):
        parser.exit(
            2, "Probe evaluation failed: check trusted local bundles and fixture binding.\n"
        )
    print(
        "Measured synthetic selection diagnostics written; "
        "not independent test or real anomaly quality."
    )


if __name__ == "__main__":
    main()
