"""Training-only operating points and explicit decision/model binding."""

import json
from pathlib import Path

import pytest
import torch

from ml.datasets import DatasetSplit
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.line_threshold import (
    fit_line_operating_point,
    load_operating_point,
    predict_with_operating_point,
    save_operating_point,
    select_threshold,
    verify_operating_point,
)
from ml.training.localization import LinePolicy, predict_lines, train_line_localizer
from ml.training.localization_evaluation import evaluate_localization
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model


@pytest.mark.parametrize(("rate", "expected"), [(0, 0.9), (0.25, 0.6), (0.5, 0.6), (1, 0.5)])
def test_threshold_ties_use_strict_greater_than(rate: float, expected: float) -> None:
    scores = [0.2, 0.6, 0.6, 0.9]
    threshold = select_threshold(scores, rate)
    assert threshold == expected
    assert sum(score > threshold for score in scores) <= int(rate * len(scores))


@pytest.mark.parametrize(
    ("scores", "rate"), [([], 0), ([float("nan")], 0), ([0.5], -1), ([0.5], float("nan"))]
)
def test_invalid_threshold_input(scores: list[float], rate: float) -> None:
    with pytest.raises(ValueError):
        select_threshold(scores, rate)


def test_train_only_fit_binding_roundtrip_and_explicit_evaluation(tmp_path: Path) -> None:
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=32)
    )
    pretrained = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    model = train_line_localizer(
        splits,
        pretrained,
        (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED),
        policy=LinePolicy(epochs=1, feature_version="stable-lines-0.1.0"),
    )
    weights = {key: value.clone() for key, value in model.head.state_dict().items()}
    point = fit_line_operating_point(model, splits)
    assert point.selected_alert_lines == 0
    assert point.fitted_partition == "train"
    assert point.deployment_ready is False
    # Both validation and test texts are unreadable, but fitting must remain identical.
    changed = splits.model_copy(
        update={
            "partitions": tuple(
                partition.model_copy(
                    update={
                        "records": tuple(
                            record.model_copy(
                                update={
                                    "sanitized_text": "not parseable",
                                    "sanitized_sha256": digest(record.record_id),
                                }
                            )
                            for record in partition.records
                        )
                    }
                )
                if partition.split is not DatasetSplit.TRAIN
                else partition
                for partition in splits.partitions
            )
        }
    )
    assert point == fit_line_operating_point(model, changed)
    path = tmp_path / "threshold.json"
    save_operating_point(point, path)
    assert load_operating_point(path) == point
    with pytest.raises(FileExistsError):
        save_operating_point(point, path)
    record = next(p.records[0] for p in splits.partitions if p.split is DatasetSplit.TRAIN)
    original_scores = predict_lines(model, record)
    decisions = predict_with_operating_point(model, record, point)
    assert [item.changed_score for item in decisions] == [
        item.changed_score for item in original_scores
    ]
    assert not any(item.predicted_changed for item in decisions)
    report = evaluate_localization(model, splits, operating_point=point)
    assert report.threshold == point.threshold
    assert report.operating_point == point
    assert model.report.threshold == 0.5
    assert all(torch.equal(value, model.head.state_dict()[key]) for key, value in weights.items())
    verify_operating_point(point, model)
    with torch.no_grad():
        model.head.bias.add_(0.01)
    with pytest.raises(ValueError, match="different model"):
        verify_operating_point(point, model)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"] += " "
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        load_operating_point(path)
