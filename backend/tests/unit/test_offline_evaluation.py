"""Hand-computed offline metrics, explicit cohorts and leakage boundaries."""

from hashlib import sha256

import pytest
from pydantic import ValidationError

from ml.evaluation.contracts import (
    EvaluationBatch,
    EvaluationCase,
    EvaluationProtocol,
    Identity,
    LineAnnotation,
    ParserCoverage,
)
from ml.evaluation.metrics import evaluate


def digest(value):
    return sha256(value.encode()).hexdigest()


def identity(value):
    return Identity(**{key: digest(key + value) for key in Identity.model_fields})


def protocol(**updates):
    values = dict(
        model_version="hand-check-1",
        model_sha256=digest("model"),
        dataset_manifest_sha256=digest("manifest"),
        threshold_policy_sha256=digest("fixed-thresholds"),
        classes=("routing", "management"),
        category_thresholds=(0.5, 0.5),
        train=(identity("train"),),
        selection=(identity("selection"),),
        precision_at_k=(1, 2, 10),
        reliability_bins=2,
    )
    values.update(updates)
    return EvaluationProtocol(**values)


def case(value, **updates):
    values = dict(
        case_id=digest(value),
        identity=identity(value),
        source_review_sha256=digest("source-review"),
        annotation_sha256=digest("annotation"),
        cohort="synthetic",
        vendor="cisco",
        device_role="edge",
        anomaly_truth=False,
        category_truth=(),
        detection_score=0.1,
        category_scores=(0.1, 0.1),
    )
    values.update(updates)
    return EvaluationCase(**values)


def batch(rows, **updates):
    return EvaluationBatch(protocol=protocol(**updates), cases=tuple(rows))


def test_exact_metrics_are_separate_not_accuracy_only():
    rows = [
        case(
            "a",
            anomaly_truth=True,
            category_truth=("routing",),
            category_scores=(0.9, 0.1),
            detection_score=0.9,
            unknown_truth=True,
            unknown_score=0.8,
            analysis_seconds=1,
            parser_coverage=ParserCoverage(significant_lines=10, recognized_lines=8),
        ),
        case(
            "b",
            anomaly_truth=True,
            category_truth=("management",),
            category_scores=(0.8, 0.4),
            detection_score=0.8,
            unknown_truth=False,
            unknown_score=0.8,
            analysis_seconds=3,
            parser_coverage=ParserCoverage(significant_lines=2, recognized_lines=2),
        ),
        case(
            "c",
            category_scores=(0.7, 0.1),
            detection_score=0.7,
            unknown_truth=False,
            unknown_score=0.1,
        ),
        case("d", detection_score=0.1, unknown_truth=False, unknown_score=0.05),
    ]
    report = evaluate(batch(rows))
    summary = report.cohorts["synthetic"].summary
    routing, management = summary.categories
    assert (routing.true_positive, routing.false_positive, routing.false_negative) == (1, 2, 0)
    assert routing.precision == pytest.approx(1 / 3)
    assert routing.recall == 1 and routing.f1 == 0.5
    assert routing.average_precision == 1 and routing.pr_auc_trapezoidal == 1
    assert management.false_negative == 1 and management.f1 == 0
    assert summary.macro_f1 == 0.25
    assert summary.detection.f1 == pytest.approx(0.8)
    assert summary.false_positives_per_device == 0.25
    assert summary.false_positives_per_configuration == 0.25
    # AP and linear PR integration are deliberately distinct for tied scores.
    assert summary.unknown_ranking.average_precision == 0.5
    assert summary.unknown_ranking.pr_auc_trapezoidal == 0.75
    assert summary.unknown_ranking.precision_at_k[2].precision == 0.5
    assert summary.unknown_ranking.precision_at_k[10].precision is None
    assert summary.unknown_ranking.precision_at_k[10].reason == "insufficient_scored_cases"
    assert summary.latency.measured_cases == 2 and summary.latency.mean_seconds == 2
    assert summary.parser_coverage.micro_fraction == pytest.approx(10 / 12)
    assert summary.parser_coverage.macro_fraction == 0.9
    # Low bin: .1 vs 0; high bin: .8 vs 2/3 => .025 + .1.
    assert summary.detection.calibration.ece == pytest.approx(0.125)
    assert sum(item.count for item in summary.detection.calibration.bins) == 4
    assert report.cohorts["real_confirmed"].summary is None
    assert report.cohorts["real_confirmed"].status == "missing"
    assert report.production_quality_proven is False


def test_real_lab_vendor_role_and_unseen_slices_never_pool_origins():
    report = evaluate(
        batch(
            [
                case("s", anomaly_truth=True, category_truth=("routing",), detection_score=0.9),
                case("r", cohort="real_confirmed", vendor="juniper", device_role=None),
                case("l", cohort="laboratory"),
            ]
        )
    )
    assert report.cohorts["synthetic"].summary.configurations == 1
    assert report.cohorts["real_confirmed"].summary.configurations == 1
    assert report.cohorts["laboratory"].summary.configurations == 1
    assert report.cohorts["real_confirmed"].by_vendor["juniper"].configurations == 1
    assert report.cohorts["real_confirmed"].by_vendor["cisco"] is None
    assert set(report.cohorts["real_confirmed"].by_role) == {"unrecorded"}
    assert report.cohorts["synthetic"].unseen_sites.configurations == 1


def test_line_metrics_keep_missing_predictions_and_deletions_visible():
    report = evaluate(
        batch(
            [
                case(
                    "l",
                    anomaly_truth=True,
                    lines=LineAnnotation(
                        total_lines=6,
                        ignored_lines=(1,),
                        positive_lines=(2, 3),
                        scored_lines=(2, 4, 5),
                        predicted_lines=(2, 4),
                    ),
                ),
                case(
                    "d", anomaly_truth=True, lines=LineAnnotation(total_lines=2, deletion_only=True)
                ),
                case("n"),
            ]
        )
    )
    lines = report.cohorts["synthetic"].summary.localization
    assert (lines.true_positive, lines.false_positive, lines.false_negative) == (1, 1, 1)
    assert lines.precision == lines.recall == lines.f1 == 0.5
    assert lines.unscored_eligible_lines == 2 and lines.unscored_positive_lines == 1
    assert lines.missing_annotation_cases == 1 and lines.excluded_deletion_cases == 1


def test_rank_scores_do_not_get_probability_calibration():
    report = evaluate(batch([case("a")], score_kind="ranking"))
    metric = report.cohorts["synthetic"].summary.detection
    assert metric.calibration is None
    assert metric.average_precision is None and metric.pr_auc_trapezoidal is None
    assert metric.ranking_unavailable_reason == "requires_positive_and_negative_cases"


def test_undefined_denominators_are_not_perfect_scores():
    report = evaluate(batch([case("a", detection_score=0)]))
    metric = report.cohorts["synthetic"].summary.detection
    assert metric.precision is None and metric.recall is None and metric.f1 is None
    assert report.cohorts["synthetic"].summary.macro_f1 is None
    assert report.cohorts["synthetic"].summary.macro_f1_defined_classes == 0


@pytest.mark.parametrize("field", tuple(Identity.model_fields))
def test_test_partition_rejects_every_leaking_identity_dimension(field):
    leaked = identity("a").model_copy(update={field: getattr(identity("train"), field)})
    with pytest.raises(ValueError, match="exposure"):
        evaluate(batch([case("a", identity=leaked)]))


def test_validation_reuse_is_diagnostic_not_independent_test():
    row = case("a", identity=identity("selection"))
    with pytest.raises(ValueError, match="exposure"):
        evaluate(batch([row]))
    report = evaluate(batch([row], purpose="validation_diagnostic"))
    assert report.independent_test is False
    assert report.partition == "validation"
    assert report.cohorts["synthetic"].unseen_sites is None


@pytest.mark.parametrize(
    "updates",
    [
        {"detection_score": float("nan")},
        {"detection_score": float("inf")},
        {"detection_score": -0.1},
        {"anomaly_truth": "false"},
        {"anomaly_truth": False, "category_truth": ("routing",)},
        {"unknown_truth": True},
        {"analysis_seconds": -1},
        {"cohort": "real_confirmed", "annotation_sha256": None},
    ],
)
def test_invalid_case_is_rejected(updates):
    with pytest.raises(ValidationError):
        case("a", **updates)


@pytest.mark.parametrize(
    "updates",
    [
        {"category_scores": (0.1,)},
        {"category_scores": (0.1, 2)},
        {"anomaly_truth": True, "category_truth": ("unknown-class",)},
        {"category_truth": ("routing", "routing"), "anomaly_truth": True},
    ],
)
def test_case_catalog_alignment_is_checked(updates):
    with pytest.raises(ValueError):
        evaluate(batch([case("a", **updates)]))


def test_mutable_model_copy_is_revalidated_and_duplicate_rows_are_rejected():
    row = case("a")
    with pytest.raises(ValueError, match="unique"):
        evaluate(batch([row, row]))
    good = batch([row])
    forged = good.model_copy(
        update={"protocol": good.protocol.model_copy(update={"detection_threshold": float("nan")})}
    )
    with pytest.raises(ValueError):
        evaluate(forged)


@pytest.mark.parametrize(
    "updates",
    [
        {"ignored_lines": (0,)},
        {"positive_lines": (2, 2)},
        {"positive_lines": (2,), "ignored_lines": (2,)},
        {"scored_lines": (1,), "predicted_lines": (2,)},
        {"deletion_only": True, "positive_lines": (1,)},
        {"scored_lines": (4,)},
    ],
)
def test_line_contract_prevents_cherry_picking_and_invalid_anchors(updates):
    with pytest.raises(ValueError):
        LineAnnotation(total_lines=3, **updates)


def test_missing_coverage_and_tied_rank_precision_are_explicit():
    report = evaluate(
        batch(
            [
                case("a", anomaly_truth=True, unknown_truth=True, unknown_score=0.5),
                case("b", unknown_truth=False, unknown_score=0.5),
                case("c", unknown_truth=False),
            ]
        )
    )
    summary = report.cohorts["synthetic"].summary
    assert summary.latency.mean_seconds is None and summary.parser_coverage.micro_fraction is None
    rank = summary.unknown_ranking
    assert rank.annotated_cases == 3 and rank.scored_cases == 2
    assert rank.precision_at_k[1].precision == 0.5  # Fractional tie, no ID ordering luck.
    assert rank.precision_at_k[1].boundary_tie_size == 2


def test_order_invariance_and_hash_binding():
    a, b = case("a"), case("b", analysis_seconds=0.5)
    first = evaluate(batch([a, b]))
    assert evaluate(batch([b, a])) == first
    changed = evaluate(batch([a, b.model_copy(update={"analysis_seconds": 1})]))
    assert changed.input_sha256 != first.input_sha256
    assert not any(
        getattr(a.identity, key) in first.model_dump_json() for key in Identity.model_fields
    )
