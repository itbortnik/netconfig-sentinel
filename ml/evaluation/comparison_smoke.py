"""Owned shared-case forest/native/external diagnostics, not a real independent benchmark."""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path
from time import perf_counter

from app.detection.baseline import PeerGroupKey
from app.detection.statistical.artifact import export_forest
from app.detection.statistical.features import extract_structured_features
from app.detection.statistical.isolation_forest import fit_isolation_forest
from app.domain import CanonicalConfig, Vendor
from app.explanation.vector_index import RetrievalUnavailable
from app.parsers import parse_configuration

from ml.datasets import DatasetSplit, ImportedDatasetRecord
from ml.evaluation.comparison import (
    ComparisonInput,
    ComparisonTruth,
    DetectionPrediction,
    DetectorRun,
)
from ml.evaluation.comparison_cli import main as compare_main
from ml.evaluation.comparison_cli import safe_path
from ml.evaluation.contracts import EvaluationProtocol
from ml.evaluation.metrics import canonical_hash
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.evaluation.probe_validation import _identity
from ml.inference.change_cli import _native_inventory
from ml.mutation import MutationType
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    MultiTaskFixtureTransferReport,
    _verified_report,
    load_multitask,
    multitask_identity,
    validate_supervised_rows,
)
from ml.training.pretraining_smoke import pretraining_fixtures
from ml.training.pretraining_transfer import objective_split_identity


def owned_canonical(record: ImportedDatasetRecord) -> CanonicalConfig:
    config = parse_configuration(record.sanitized_text, filename="owned.cfg")
    # Explicit laboratory grouping, not discovery or asserted real site/service inventory.
    return config.model_copy(
        update={
            "device": config.device.model_copy(
                update={
                    "role": record.device_role,
                    "site_class": "owned-comparison",
                    "service_profile": "authored-static-bgp",
                }
            )
        }
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-model", type=Path, required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--foundation-model", type=Path)
    parser.add_argument("--foundation-sha256")
    parser.add_argument("--foundation-source", type=Path)
    parser.add_argument("--fixture-admission", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        safe_path(args.output)
        if args.output.exists() or not args.output.parent.is_dir():
            raise ValueError("owned comparison output must be new")
        external = (args.foundation_model, args.foundation_sha256, args.foundation_source)
        if (
            args.fixture_admission is not None and any(value is not None for value in external)
        ) or (args.fixture_admission is None and any(value is None for value in external)):
            raise ValueError("choose explicit fixture admission or the complete external inputs")
        _native_inventory(args.native_model)
        native = load_multitask(args.native_model)
        if multitask_identity(native) != args.native_sha256:
            raise ValueError("native independent identity differs")
        if native.report.head_policy.classes != ("telnet_enabled",):
            raise ValueError("owned comparison requires the exact authored Telnet objective")
        fixture_source = None
        if args.fixture_admission is not None:
            from ml.registry.admission import load_fixture_admission
            from ml.training.fixture_transfer_smoke import authored_transfer_splits

            report = _verified_report(native)
            if not isinstance(report, MultiTaskFixtureTransferReport):
                raise ValueError("fixture comparison requires the explicit fixture training format")
            admission = load_fixture_admission(args.fixture_admission, native)
            splits = authored_transfer_splits()
            examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
            if objective_split_identity(admission.splits) != objective_split_identity(splits) or (
                admission.examples != examples
            ):
                raise ValueError(
                    "owned fixture comparison requires exact authored downstream inputs"
                )
            native_batch = build_multitask_validation(
                native, splits, examples, fixture_corpus=admission.corpus
            )
            fixture_source = report.pretraining
            batches = [("native_encoder", native_batch)]
        else:
            from ml.evaluation.foundation_validation import build_foundation_validation
            from ml.training.foundation_transfer import load_foundation_transfer

            foundation = load_foundation_transfer(
                args.foundation_model,
                source_root=args.foundation_source,
                expected_identity=args.foundation_sha256,
            )
            if foundation.report.head_policy.classes != ("telnet_enabled",):
                raise ValueError("owned comparison requires the exact authored Telnet objective")
            splits, _ = pretraining_fixtures()
            examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
            native_batch = build_multitask_validation(native, splits, examples)
            foundation_batch = build_foundation_validation(foundation, splits, examples)
            batches = [("native_encoder", native_batch), ("external_encoder", foundation_batch)]
        rows = validate_supervised_rows(splits, examples, native.report.head_policy)
        validation_records = {
            canonical_hash(
                (row.record.source_id, row.record.record_id, row.record.sanitized_sha256)
            ): row.record
            for row in rows[DatasetSplit.VALIDATION]
        }
        training = next(
            part.records for part in splits.partitions if part.split is DatasetSplit.TRAIN
        )
        # One actual forest per vendor, fitted only on original owned train parents.
        forests = {
            vendor.value: export_forest(
                fit_isolation_forest(
                    [owned_canonical(row) for row in training if row.vendor_hint is vendor]
                )
            )
            for vendor in (Vendor.CISCO, Vendor.JUNIPER)
        }
        forest_predictions = []
        for row in native_batch.cases:
            record = validation_records[row.case_id]
            started = perf_counter()
            config = owned_canonical(record)
            features = [extract_structured_features(config).as_row()]
            forest = forests[row.vendor]
            if PeerGroupKey.from_config(config) != forest.metadata.group:
                raise ValueError("owned forest input grouping differs")
            decision = forest.decision_function(features)[0]
            # Fixed offset-centered ranking transformation, not a probability/calibration.
            score = 0.5 - decision / 2
            if (score > 0.5) != (forest.predict(features)[0] == -1):
                raise ValueError("forest decision mapping differs")
            forest_predictions.append(
                DetectionPrediction(
                    case_id=row.case_id,
                    source_sha256=row.identity.source_sha256,
                    score=score,
                    analysis_seconds=perf_counter() - started,
                )
            )
        forest_contents = {
            vendor: model.model_dump(mode="json") for vendor, model in forests.items()
        }
        forest_identity = canonical_hash(
            {
                "forests": forest_contents,
                "manifest": objective_split_identity(splits),
                "scope": "owned-train-parent-per-vendor",
            }
        )
        forest_protocol = EvaluationProtocol(
            purpose="validation_diagnostic",
            target_semantics="injected_mutation",
            latency_scope="parsing_and_inference",
            model_version="owned-vendor-forest-control-0.1.0",
            model_sha256=forest_identity,
            dataset_manifest_sha256=objective_split_identity(splits),
            threshold_policy_sha256=canonical_hash(
                "offset-centered-ranking:0.5-decision/2:strict>0.5"
            ),
            score_kind="ranking",
            classes=("generic_anomaly",),
            category_thresholds=(0.5,),
            train=tuple(_identity(row, row.sanitized_sha256) for row in training),
        )
        truth = tuple(
            ComparisonTruth(
                case_id=row.case_id,
                identity=row.identity,
                source_review_sha256=row.source_review_sha256,
                annotation_sha256=row.annotation_sha256,
                cohort=row.cohort,
                vendor=row.vendor,
                device_role=row.device_role,
                anomaly_truth=row.anomaly_truth,
            )
            for row in native_batch.cases
        )
        # Reject changed ground truth/grouping/review hashes, not merely mismatched IDs.
        for _, batch in batches[1:]:
            other_truth = tuple(
                ComparisonTruth(
                    case_id=row.case_id,
                    identity=row.identity,
                    source_review_sha256=row.source_review_sha256,
                    annotation_sha256=row.annotation_sha256,
                    cohort=row.cohort,
                    vendor=row.vendor,
                    device_role=row.device_role,
                    anomaly_truth=row.anomaly_truth,
                )
                for row in batch.cases
            )
            if truth != other_truth:
                raise ValueError("native and external truth/review exposure differs")
        runs = [
            DetectorRun(
                label="isolation_forest",
                role="baseline",
                protocol=forest_protocol,
                predictions=tuple(forest_predictions),
            )
        ]
        for label, batch in batches:
            runs.append(
                DetectorRun(
                    label=label,
                    role="candidate",
                    protocol=batch.protocol,
                    predictions=tuple(
                        DetectionPrediction(
                            case_id=row.case_id,
                            source_sha256=row.identity.source_sha256,
                            score=row.detection_score,
                            analysis_seconds=row.analysis_seconds,
                        )
                        for row in batch.cases
                    ),
                )
            )
        comparison = ComparisonInput(truth=truth, runs=tuple(runs))
        args.output.mkdir(exist_ok=False)
        marker = args.output / ".incomplete"
        with marker.open("x", encoding="utf-8") as stream:
            stream.write("owned comparison writing\n")
        with (args.output / "input.json").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(comparison.model_dump_json(indent=2) + "\n")
        import json

        with (args.output / "forest.json").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(forest_contents, sort_keys=True, allow_nan=False) + "\n")
        if fixture_source is not None:
            with (args.output / "fixture-source.json").open(
                "x", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write(fixture_source.model_dump_json(indent=2) + "\n")
        if compare_main(
            [
                "--input",
                str(args.output / "input.json"),
                "--output",
                str(args.output / "report.json"),
            ]
        ):
            raise ValueError("comparison refused")
        marker.unlink()
    except (
        OSError,
        ValueError,
        RuntimeError,
        RetrievalUnavailable,
        pickle.UnpicklingError,
        EOFError,
        RecursionError,
    ):
        parser.exit(
            2, "Owned comparison failed: check exact trusted models, pins and unused output.\n"
        )
    print(
        "Actual shared selection diagnostics for the explicitly selected models; "
        "no real/independent quality or safety claim."
    )


if __name__ == "__main__":
    main()
