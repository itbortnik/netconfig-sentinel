"""Metric floors for a fixed authored diagnostic, never a real-network quality gate."""

import pytest

from ml.datasets import DatasetSplit, deduplicate_dataset, split_deduplicated_dataset
from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType
from ml.training import lexical_localization
from ml.training.classification import ProbePolicy, prepare_examples
from ml.training.localization_evaluation import VARIANTS, LineCase, summarize

TYPES = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
TRAIN_SHA256 = "2a900a6ee315bcafdae3b91c027ae8c83952b51f8ebb95e56f2176d195fa1217"
VALIDATION_SHA256 = "85be92315b16d9e3fa825a3276a8692d17cf49a9842971530cfd7097b1c88b30"


@pytest.fixture(scope="module")
def fitted_diagnostic():
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    model, report = lexical_localization.train_lexical_baseline(splits)
    rows, skipped = prepare_examples(splits, TYPES, ProbePolicy())
    assert not skipped
    return model, report, rows[DatasetSplit.VALIDATION]


def _assert_metric_floor(cases: tuple[LineCase, ...]) -> None:
    # These are the published six selection views of two authored devices.
    # Each formatting variant is checked separately, not counted as new data.
    assert len(cases) == 6 * len(VARIANTS)
    assert {case.variant for case in cases} == set(VARIANTS)
    for variant in VARIANTS:
        selected = tuple(case for case in cases if case.variant == variant)
        assert len({(case.source_id, case.device_id, case.mutation) for case in selected}) == 6
        assert {case.mutation for case in selected} == {
            "no_injected_mutation",
            *(kind.value for kind in TYPES),
        }
        summary = summarize(selected)
        assert summary.configurations == 6
        assert summary.unique_devices == 2
        assert summary.reference_configurations == 2
        assert summary.excluded_deletion_only == 0
        assert summary.true_positive + summary.false_negative == 4
        expected_negatives = 99 if variant == "comment_context" else 93
        assert summary.true_negative + summary.false_positive == expected_negatives
        assert summary.unscorable_lines == (12 if variant == "leading_blank" else 0)
        assert summary.f1 >= 0.75, (variant, summary)
        assert summary.recall == 1.0, (variant, summary)
        assert summary.false_positives_per_configuration <= 1 / 3, (variant, summary)
        assert {case.vendor for case in selected} == {"cisco", "juniper"}
        for vendor in ("cisco", "juniper"):
            vendor_cases = tuple(case for case in selected if case.vendor == vendor)
            by_vendor = summarize(vendor_cases)
            assert by_vendor.configurations == 3
            assert by_vendor.unique_devices == 1
            assert by_vendor.true_positive + by_vendor.false_negative == 2
            assert by_vendor.recall == 1.0
            for mutation in TYPES:
                changed = next(case for case in vendor_cases if case.mutation == mutation.value)
                assert len(changed.true_positive) + len(changed.false_negative) == 1


def test_trained_lexical_predictor_preserves_published_diagnostic_floor(fitted_diagnostic):
    _, report, _ = fitted_diagnostic
    assert report["version"] == "lexical-lines-0.1.0"
    assert report["train_fingerprint"] == TRAIN_SHA256
    assert report["validation_fingerprint"] == VALIDATION_SHA256
    assert (report["train_lines"], report["train_positive_lines"]) == (328, 16)
    assert report["threshold"] == 0.5  # No threshold selection on these views.
    assert report["synthetic_only"] is True
    assert report["independent_test"] is False
    assert report["calibrated_probability"] is False
    _assert_metric_floor(tuple(LineCase.model_validate(case) for case in report["cases"]))


@pytest.mark.parametrize("damage", ("all_negative", "all_positive", "inverted"))
def test_metric_floor_rejects_degenerate_actual_prediction_paths(
    fitted_diagnostic, monkeypatch, damage
):
    model, _, rows = fitted_diagnostic
    predict = lexical_localization.predict_lexical_lines

    def degraded(selected, record):
        outputs = []
        for line in predict(selected, record):
            if line.changed_score is None:
                outputs.append(line)
                continue
            score = (
                0.0
                if damage == "all_negative"
                else 1.0
                if damage == "all_positive"
                else 1.0 - line.changed_score
            )
            outputs.append(
                line.model_copy(update={"changed_score": score, "predicted_changed": score > 0.5})
            )
        return tuple(outputs)

    monkeypatch.setattr(lexical_localization, "predict_lexical_lines", degraded)
    report = lexical_localization.lexical_diagnostics(model, rows, TYPES)
    cases = tuple(LineCase.model_validate(case) for case in report["cases"])
    # Cardinalities still match: failure must be due to actual degraded metrics.
    assert summarize(cases).configurations == 24
    assert summarize(cases).unique_devices == 2
    with pytest.raises(AssertionError):
        _assert_metric_floor(cases)
