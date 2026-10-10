"""Explicit offline approved-fixture encoder -> owned synthetic heads/selection demonstration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.datasets import (
    DatasetSplitResult,
    ImportedDatasetFixtureRecord,
    ImportedDatasetRecord,
    deduplicate_dataset,
    load_dataset_fixture_manifest,
    split_deduplicated_dataset,
)
from ml.datasets.fixture_training import FixtureTrainingCorpus, prepare_fixture_training_corpus
from ml.evaluation.cli import write_report
from ml.evaluation.metrics import evaluate
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.mutation import MutationType
from ml.preprocessing import sanitize_configuration
from ml.preprocessing.blocks import digest
from ml.training.fixture_pretraining_cli import _read_json
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    FineTunePolicy,
    load_multitask,
    multitask_identity,
    predict_multitask,
    save_multitask,
    train_multitask,
)
from ml.training.pretraining import load_fixture_pretraining, pretraining_identity
from ml.training.pretraining_smoke import pretraining_fixtures


def authored_transfer_splits() -> DatasetSplitResult:
    """Original 24 owned fixtures, not new independent networks or real healthy labels."""
    original, _ = pretraining_fixtures()
    records: list[ImportedDatasetRecord] = []
    for part in original.partitions:
        for row in part.records:
            sanitized = sanitize_configuration(
                row.sanitized_text,
                topology_id=f"{row.source_id}\0{row.network_id}",
                pseudonymization_key=b"owned-fixture-transfer-synthetic-test-key",
            )
            records.append(
                row.model_copy(
                    update={
                        "source_id": "synthetic-fixture-transfer",
                        "sanitized_text": sanitized.text,
                        "sanitized_sha256": digest(sanitized.text),
                        "replacements": sanitized.replacements,
                        "sanitization_version": sanitized.version,
                    }
                )
            )
    return split_deduplicated_dataset(records, deduplicate_dataset(records))


def load_retained_fixture_corpus(
    manifest: Path,
    records: Path,
    source_model: Path,
) -> FixtureTrainingCorpus:
    source = load_fixture_pretraining(source_model)
    payload = _read_json(records, 64 * 1024 * 1024)
    if not isinstance(payload, list) or not 1 <= len(payload) <= 2048:
        raise ValueError("retained fixture inputs must be a complete bounded list")
    imported = tuple(ImportedDatasetFixtureRecord.model_validate(row) for row in payload)
    corpus = prepare_fixture_training_corpus(
        load_dataset_fixture_manifest(manifest),
        imported,
        policy=source.report.corpus.policy,
    )
    if corpus.audit != source.report.corpus:
        raise ValueError("retained source fixtures differ from the actual pretrained model")
    return corpus


def run_fixture_transfer(
    source_model: Path,
    expected_identity: str,
    manifest: Path,
    records: Path,
    output: Path,
    *,
    epochs: int = 20,
) -> dict[str, object]:
    """Fixed authored scenario; no arbitrary customer inputs or registry enrollment."""
    source = load_fixture_pretraining(source_model)
    if pretraining_identity(source) != expected_identity:
        raise ValueError("fixture source independent model pin differs")
    corpus = load_retained_fixture_corpus(manifest, records, source_model)
    splits = authored_transfer_splits()
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    output.mkdir(exist_ok=False)
    marker = output / ".incomplete"
    marker.write_text("fixture transfer running\n", encoding="utf-8")
    protocol = {
        "epochs": epochs,
        "head_classes": ["telnet_enabled"],
        "severity_weight": 0,
        "source_identity": expected_identity,
        "purpose": "validation_diagnostic",
        "fixed_threshold": 0.5,
        "test_labels_used": False,
    }
    (output / "protocol.json").write_text(json.dumps(protocol, sort_keys=True), encoding="utf-8")
    result = train_multitask(
        splits,
        source,
        examples,
        fixture_corpus=corpus,
        head_policy=HeadPolicy(classes=("telnet_enabled",), max_examples=128),
        training_policy=FineTunePolicy(epochs=epochs),
        loss_weights=LossWeights(severity=0),
    )
    identity = multitask_identity(result)
    save_multitask(result, output / "model")
    restored = load_multitask(output / "model")
    if multitask_identity(restored) != identity or any(
        predict_multitask(restored, row.record) != predict_multitask(result, row.record)
        for row in examples
    ):
        raise ValueError("fixture transfer saved model/predictions differ")
    batch = build_multitask_validation(restored, splits, examples, fixture_corpus=corpus)
    report = evaluate(batch)
    (output / "predictions.json").write_text(batch.model_dump_json(), encoding="utf-8")
    write_report(report, output / "metrics.json", output / "reliability.svg")
    result_summary: dict[str, object] = {
        "version": "owned-fixture-transfer-run-0.1.0",
        "source_identity": expected_identity,
        "model_identity": identity,
        "training_format": result.report.version,
        "train_examples": result.report.train_examples,
        "selection_examples": result.report.validation_examples,
        "trainable_parameters": result.report.trainable_parameters,
        "total_parameters": result.report.parameter_count,
        "best_epoch": result.report.best_epoch,
        "source_unchanged": pretraining_identity(source) == expected_identity,
        "round_trip_predictions_equal": True,
        "independent_test": False,
        "real_confirmed_quality": None,
        "online_activation": False,
    }
    (output / "run.json").write_text(json.dumps(result_summary, sort_keys=True), encoding="utf-8")
    marker.unlink()
    return result_summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-model", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=20)
    args = parser.parse_args()
    try:
        result = run_fixture_transfer(
            args.source_model,
            args.source_sha256,
            args.manifest,
            args.records,
            args.output,
            epochs=args.epochs,
        )
    except (ValueError, OSError, RuntimeError):
        parser.exit(1, "Fixture transfer failed; inspect trusted local source/exposure bindings.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
