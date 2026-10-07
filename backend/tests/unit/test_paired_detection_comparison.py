"""Hand-computed shared-case comparisons do not invent baseline category/line outputs."""

from hashlib import sha256

import pytest

from ml.evaluation.comparison import (
    ComparisonInput,
    ComparisonTruth,
    DetectionPrediction,
    DetectorRun,
    compare_detectors,
)
from ml.evaluation.contracts import EvaluationProtocol, Identity


def digest(value):
    return sha256(value.encode()).hexdigest()


def identity(value):
    return Identity(**{name: digest(name + value) for name in Identity.model_fields})


def inputs():
    truth = tuple(
        ComparisonTruth(
            case_id=digest(key),
            identity=identity(key),
            source_review_sha256=digest("review"),
            annotation_sha256=digest("truth" + key),
            cohort="synthetic",
            vendor="cisco",
            device_role="edge",
            anomaly_truth=positive,
        )
        for key, positive in (("a", True), ("b", True), ("c", False), ("d", False))
    )

    def run(label, role, scores, kind):
        protocol = EvaluationProtocol(
            model_version=label,
            model_sha256=digest(label),
            dataset_manifest_sha256=digest("manifest"),
            threshold_policy_sha256=digest(label + "threshold"),
            classes=("generic_anomaly",),
            category_thresholds=(0.5,),
            train=(identity("train"),),
            score_kind=kind,
            target_semantics="injected_mutation",
        )
        return DetectorRun(
            label=label,
            role=role,
            protocol=protocol,
            predictions=tuple(
                DetectionPrediction(
                    case_id=row.case_id,
                    source_sha256=row.identity.source_sha256,
                    score=score,
                    analysis_seconds=0.1 if role == "baseline" else 0.3,
                )
                for row, score in zip(truth, scores, strict=True)
            ),
        )

    return ComparisonInput(
        truth=truth,
        runs=(
            run("forest", "baseline", (0.8, 0.2, 0.7, 0.1), "ranking"),
            run("encoder", "candidate", (0.9, 0.8, 0.1, 0.1), "probability"),
        ),
    )


def test_shared_denominators_exact_deltas_separate_origins_and_no_fake_heads():
    result = compare_detectors(inputs())
    summary = result.cohorts["synthetic"].summary
    assert summary.configurations == 4 and summary.unique_devices == 4
    baseline, candidate = summary.models["forest"], summary.models["encoder"]
    assert baseline.detection.f1 == 0.5 and candidate.detection.f1 == 1
    assert candidate.difference_from_baseline.f1 == 0.5
    assert baseline.detection.calibration is None
    assert candidate.detection.calibration is not None
    assert candidate.difference_from_baseline.false_positives_per_device == -0.25
    assert candidate.difference_from_baseline.mean_seconds == pytest.approx(0.2)
    assert result.cohorts["real_confirmed"].status == "missing"
    assert not result.production_quality_proven and not result.external_pretraining_isolation_proven
    serialized = result.model_dump_json()
    assert "category_scores" not in serialized and "line_scores" not in serialized
    assert "family_key" not in serialized and "case_id" not in serialized


@pytest.mark.parametrize(
    "damage",
    (
        "missing",
        "extra",
        "source",
        "manifest",
        "purpose",
        "truth",
        "leak",
        "duplicate_model",
        "two_baselines",
    ),
)
def test_no_intersection_or_silent_protocol_switch_can_hide_mismatches(damage):
    original = inputs()
    candidate = original.runs[1]
    rows = candidate.predictions
    if damage == "missing":
        candidate = candidate.model_copy(update={"predictions": rows[:-1]})
    elif damage == "extra":
        candidate = candidate.model_copy(update={"predictions": (*rows, rows[0])})
    elif damage == "source":
        candidate = candidate.model_copy(
            update={
                "predictions": (rows[0].model_copy(update={"source_sha256": "0" * 64}), *rows[1:])
            }
        )
    elif damage in ("manifest", "purpose", "truth", "leak"):
        change = {
            "manifest": {"dataset_manifest_sha256": "0" * 64},
            "purpose": {"purpose": "validation_diagnostic"},
            "truth": {"target_semantics": "confirmed_anomaly"},
            "leak": {"train": (original.truth[0].identity,)},
        }[damage]
        candidate = candidate.model_copy(
            update={"protocol": candidate.protocol.model_copy(update=change)}
        )
    elif damage == "duplicate_model":
        candidate = candidate.model_copy(
            update={
                "protocol": candidate.protocol.model_copy(
                    update={"model_sha256": original.runs[0].protocol.model_sha256}
                )
            }
        )
    else:
        candidate = candidate.model_copy(update={"role": "baseline"})
    with pytest.raises(ValueError):
        compare_detectors(original.model_copy(update={"runs": (original.runs[0], candidate)}))


def test_comparison_order_is_canonical_and_undefined_denominators_stay_missing():
    original = inputs()
    reordered = original.model_copy(
        update={
            "truth": tuple(reversed(original.truth)),
            "runs": tuple(
                row.model_copy(update={"predictions": tuple(reversed(row.predictions))})
                for row in reversed(original.runs)
            ),
        }
    )
    assert compare_detectors(original) == compare_detectors(reordered)
    one_class = original.model_copy(
        update={
            "truth": tuple(
                row.model_copy(update={"anomaly_truth": False}) for row in original.truth
            )
        }
    )
    result = compare_detectors(one_class)
    assert result.cohorts["synthetic"].summary.models["encoder"].detection.average_precision is None
    assert (
        result.cohorts["synthetic"]
        .summary.models["encoder"]
        .difference_from_baseline.average_precision
        is None
    )


def test_common_unseen_sites_use_union_of_every_model_selection_exposure():
    original = inputs()
    runs = tuple(
        run.model_copy(
            update={
                "protocol": run.protocol.model_copy(
                    update={
                        "purpose": "validation_diagnostic",
                        "selection": (original.truth[0].identity,)
                        if run.role == "candidate"
                        else (),
                    }
                )
            }
        )
        for run in original.runs
    )
    result = compare_detectors(original.model_copy(update={"runs": runs}))
    cohort = result.cohorts["synthetic"]
    assert cohort.summary.configurations == 4 and cohort.common_unseen_sites.configurations == 3
    assert set(cohort.common_unseen_sites.models) == {"encoder", "forest"}


def test_missing_role_does_not_merge_with_a_legitimate_unrecorded_role_label():
    original = inputs()
    changed = original.model_copy(
        update={
            "truth": (
                original.truth[0].model_copy(update={"device_role": None}),
                original.truth[1].model_copy(update={"device_role": "unrecorded"}),
                *original.truth[2:],
            )
        }
    )
    roles = compare_detectors(changed).cohorts["synthetic"].by_role
    assert roles["unrecorded"].configurations == 1
    assert roles["<unrecorded>"].configurations == 1
    assert roles["edge"].configurations == 2


def test_cli_private_new_output_and_corrupt_input_are_generic(tmp_path, capsys):
    from ml.evaluation.comparison_cli import main

    path = tmp_path / "input.json"
    output = tmp_path / "result.json"
    path.write_text(inputs().model_dump_json(), encoding="utf-8")
    assert main(["--input", str(path), "--output", str(output)]) == 0
    assert output.exists()
    assert main(["--input", str(path), "--output", str(output)]) == 2
    path.write_text('{"truth": [], "truth": []}', encoding="utf-8")
    assert main(["--input", str(path), "--output", str(tmp_path / "bad.json")]) == 2
    assert not (tmp_path / "bad.json").exists()
    printed = capsys.readouterr()
    assert str(tmp_path) not in printed.out + printed.err


@pytest.mark.parametrize("kind", ("is_symlink", "is_junction"))
@pytest.mark.parametrize("target", ("input", "output", "parent"))
def test_cli_linked_components_fail_without_any_report(tmp_path, monkeypatch, kind, target):
    from pathlib import Path

    from ml.evaluation.comparison_cli import main

    path, output = tmp_path / "input.json", tmp_path / "report.json"
    path.write_text(inputs().model_dump_json(), encoding="utf-8")
    linked = path if target == "input" else output if target == "output" else tmp_path
    original = getattr(Path, kind)
    monkeypatch.setattr(Path, kind, lambda self: self == linked or original(self))
    assert main(["--input", str(path), "--output", str(output)]) == 2
    assert not output.exists()


def test_relative_cli_paths_check_absolute_ancestors(tmp_path, monkeypatch):
    from pathlib import Path

    from ml.evaluation.comparison_cli import main

    monkeypatch.chdir(tmp_path)
    Path("input.json").write_text(inputs().model_dump_json(), encoding="utf-8")
    original = Path.is_junction
    monkeypatch.setattr(
        Path, "is_junction", lambda self: self == tmp_path.parent or original(self)
    )
    assert main(["--input", "input.json", "--output", "report.json"]) == 2
    assert not Path("report.json").exists()


def test_real_origin_declared_truth_and_missing_latency_are_not_filled_in():
    original = inputs()
    changed = original.model_copy(
        update={
            "truth": tuple(
                row.model_copy(update={"cohort": "real_confirmed", "vendor": "juniper"})
                for row in original.truth
            ),
            "runs": tuple(
                run.model_copy(
                    update={
                        "protocol": run.protocol.model_copy(
                            update={"target_semantics": "confirmed_anomaly"}
                        ),
                        "predictions": tuple(
                            row.model_copy(update={"analysis_seconds": None})
                            for row in run.predictions
                        ),
                    }
                )
                for run in original.runs
            ),
        }
    )
    result = compare_detectors(changed)
    assert result.cohorts["synthetic"].summary is None
    real = result.cohorts["real_confirmed"].summary
    assert real.configurations == 4 and real.models["forest"].latency.measured_cases == 0
    assert real.models["encoder"].difference_from_baseline.mean_seconds is None
    assert not result.production_quality_proven  # Declared fixture metadata is not real acceptance.


def test_latency_delta_requires_the_same_measured_cases_not_unmatched_averages():
    original = inputs()
    changed = original.model_copy(
        update={
            "runs": tuple(
                run.model_copy(
                    update={
                        "predictions": tuple(
                            row.model_copy(update={"analysis_seconds": None})
                            if index == (0 if run.role == "baseline" else 1)
                            else row
                            for index, row in enumerate(run.predictions)
                        )
                    }
                )
                for run in original.runs
            )
        }
    )
    summary = compare_detectors(changed).cohorts["synthetic"].summary
    assert all(row.latency.measured_cases == 3 for row in summary.models.values())
    assert summary.models["encoder"].difference_from_baseline.mean_seconds is None


@pytest.mark.parametrize(
    "damage", ("duplicate_case", "extra_model", "nan", "bool_score", "role", "no_baseline")
)
def test_bounded_strict_comparison_contract_rejects_copied_invalid_objects(damage):
    original = inputs()
    if damage == "duplicate_case":
        changed = original.model_copy(update={"truth": (*original.truth[:-1], original.truth[0])})
    elif damage == "extra_model":
        changed = original.model_copy(update={"runs": original.runs * 5})
    elif damage == "no_baseline":
        changed = original.model_copy(
            update={
                "runs": tuple(run.model_copy(update={"role": "candidate"}) for run in original.runs)
            }
        )
    elif damage == "role":
        changed = original.model_copy(
            update={
                "truth": (
                    original.truth[0].model_copy(update={"device_role": "private free-text"}),
                    *original.truth[1:],
                )
            }
        )
    else:
        candidate = original.runs[1]
        row = candidate.predictions[0].model_copy(
            update={"score": float("nan") if damage == "nan" else True}
        )
        changed = original.model_copy(
            update={
                "runs": (
                    original.runs[0],
                    candidate.model_copy(update={"predictions": (row, *candidate.predictions[1:])}),
                )
            }
        )
    with pytest.raises(ValueError):
        compare_detectors(changed)


def test_owned_forest_grouping_is_explicit_not_added_to_numeric_features():
    from app.detection.baseline import PeerGroupKey
    from app.detection.statistical.features import extract_structured_features
    from app.parsers import parse_configuration

    from ml.evaluation.comparison_smoke import owned_canonical
    from ml.training.pretraining_smoke import pretraining_fixtures

    splits, _ = pretraining_fixtures()
    record = splits.partitions[0].records[0]
    original = parse_configuration(record.sanitized_text, filename="owned.cfg")
    config = owned_canonical(record)
    assert (
        extract_structured_features(config).values == extract_structured_features(original).values
    )
    assert config.device.role == record.device_role
    assert PeerGroupKey.from_config(config).device_role == record.device_role
    assert config.device.site_class == "owned-comparison"
