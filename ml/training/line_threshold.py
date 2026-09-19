"""Train-reference operating points; not probability calibration or health labels."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import _validate_split_entities
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import (
    LineResult,
    LineScore,
    load_localizer,
    localizer_identity,
    predict_lines,
)


class LineOperatingPoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["line-operating-point-0.1.0"] = "line-operating-point-0.1.0"
    fitted_partition: Literal["train"] = "train"
    calibrated_probability: Literal[False] = False
    deployment_ready: Literal[False] = False
    model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    train_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    threshold: float = Field(ge=0.5, le=1)
    target_reference_alert_rate: float = Field(ge=0, le=1)
    reference_configurations: int = Field(ge=1)
    scored_reference_lines: int = Field(ge=1)
    unscorable_reference_lines: int = Field(ge=0)
    baseline_alert_lines: int = Field(ge=0)
    selected_alert_lines: int = Field(ge=0)

    @model_validator(mode="after")
    def consistent_counts(self) -> LineOperatingPoint:
        if (
            not self.selected_alert_lines
            <= self.baseline_alert_lines
            <= self.scored_reference_lines
        ):
            raise ValueError("inconsistent reference alert counts")
        if self.selected_alert_lines > math.floor(
            self.target_reference_alert_rate * self.scored_reference_lines
        ):
            raise ValueError("training reference alert budget exceeded")
        return self


def select_threshold(scores: list[float], target_rate: float) -> float:
    """Lowest threshold >= 0.5 satisfying an empirical reference-line alert budget."""
    if not scores or not math.isfinite(target_rate) or not 0 <= target_rate <= 1:
        raise ValueError("threshold selection requires scores and a valid target rate")
    if any(not math.isfinite(score) or not 0 <= score <= 1 for score in scores):
        raise ValueError("invalid reference score")
    allowed = math.floor(target_rate * len(scores))
    if allowed == len(scores):
        return 0.5
    return max(0.5, sorted(scores, reverse=True)[allowed])


def fit_line_operating_point(
    result: LineResult,
    splits: DatasetSplitResult,
    *,
    target_reference_alert_rate: float = 0,
) -> LineOperatingPoint:
    """Score original train records only; never parse or score validation/test text."""
    select_threshold([0.5], target_reference_alert_rate)
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    _validate_split_entities(splits)
    records = sorted(
        next(
            partition.records
            for partition in splits.partitions
            if partition.split is DatasetSplit.TRAIN
        ),
        key=lambda item: (item.source_id, item.record_id),
    )
    fingerprint = digest(
        json.dumps(
            [(record.source_id, record.record_id, record.sanitized_sha256) for record in records],
            separators=(",", ":"),
        )
    )
    if fingerprint != result.pretrained.report.training_fingerprint:
        raise ValueError("operating point requires the model training corpus")
    if len(records) > result.report.policy.max_examples:
        raise ValueError("operating point example budget exceeded")
    scores: list[float] = []
    unscorable, lines = 0, 0
    for record in records:
        lines += len(record.sanitized_text.splitlines())
        if lines > result.report.policy.max_lines:
            raise ValueError("operating point line budget exceeded")
        for prediction in predict_lines(result, record):
            if prediction.changed_score is None:
                unscorable += 1
            else:
                scores.append(prediction.changed_score)
    threshold = select_threshold(scores, target_reference_alert_rate)
    return LineOperatingPoint(
        model_sha256=localizer_identity(result),
        train_fingerprint=fingerprint,
        threshold=threshold,
        target_reference_alert_rate=target_reference_alert_rate,
        reference_configurations=len(records),
        scored_reference_lines=len(scores),
        unscorable_reference_lines=unscorable,
        baseline_alert_lines=sum(score > 0.5 for score in scores),
        selected_alert_lines=sum(score > threshold for score in scores),
    )


def verify_operating_point(point: LineOperatingPoint, result: LineResult) -> None:
    LineOperatingPoint.model_validate(point.model_dump())
    if point.model_sha256 != localizer_identity(result):
        raise ValueError("operating point belongs to a different model")
    if point.train_fingerprint != result.pretrained.report.training_fingerprint:
        raise ValueError("operating point training corpus mismatch")


def save_operating_point(point: LineOperatingPoint, path: Path) -> None:
    text = LineOperatingPoint.model_validate(point.model_dump()).model_dump_json()
    with path.open("x", encoding="utf-8") as target:
        json.dump({"payload": text, "sha256": digest(text)}, target)


def predict_with_operating_point(
    result: LineResult,
    record: ImportedDatasetRecord,
    point: LineOperatingPoint,
) -> tuple[LineScore, ...]:
    verify_operating_point(point, result)
    return tuple(
        score.model_copy(
            update={
                "predicted_changed": score.changed_score > point.threshold
                if score.changed_score is not None
                else None
            }
        )
        for score in predict_lines(result, record)
    )


def load_operating_point(path: Path) -> LineOperatingPoint:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("unsafe operating point file")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if digest(envelope["payload"]) != envelope["sha256"]:
        raise ValueError("operating point checksum mismatch")
    return LineOperatingPoint.model_validate_json(envelope["payload"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    point = fit_line_operating_point(load_localizer(args.model), classification_fixtures())
    save_operating_point(point, args.output)
    print(point.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
