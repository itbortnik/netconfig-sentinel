"""Validation-only robustness diagnostics, never a held-out quality estimate."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Literal

from app.domain import Vendor
from pydantic import BaseModel, ConfigDict, Field

from ml.datasets import DatasetSplit, DatasetSplitResult
from ml.preprocessing.blocks import digest
from ml.training.classification import _encoder_hash, _fingerprint, prepare_examples
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import (
    LineReport,
    LineResult,
    line_targets,
    load_localizer,
    predict_lines,
)

Variant = Literal["original", "leading_blank", "comment_context", "crlf"]
VARIANTS: tuple[Variant, ...] = ("original", "leading_blank", "comment_context", "crlf")


class LineCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_id: str
    record_id: str
    device_id: str
    source_sha256: str
    vendor: str
    mutation: str
    variant: Variant
    true_positive: tuple[int, ...]
    false_positive: tuple[int, ...]
    false_negative: tuple[int, ...]
    true_negative: int = Field(ge=0)
    ignored_lines: int = Field(ge=0)
    unscorable_lines: int = Field(ge=0)
    deletion_only: bool


class LineSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    configurations: int
    unique_devices: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    false_positives_per_configuration: float
    reference_configurations: int
    reference_configurations_with_alerts: int
    excluded_deletion_only: int
    unscorable_lines: int


class LineDiagnostics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["line-diagnostics-0.1.0"] = "line-diagnostics-0.1.0"
    partition: Literal["validation"] = "validation"
    independent_test: Literal[False] = False
    synthetic_only: Literal[True] = True
    model_sha256: str
    validation_fingerprint: str
    threshold: float
    summary: LineSummary
    by_vendor: dict[str, LineSummary]
    by_mutation: dict[str, LineSummary]
    by_variant: dict[str, LineSummary]
    cases: tuple[LineCase, ...]


def summarize(cases: tuple[LineCase, ...]) -> LineSummary:
    included = [case for case in cases if not case.deletion_only]
    tp = sum(len(case.true_positive) for case in included)
    fp = sum(len(case.false_positive) for case in included)
    fn = sum(len(case.false_negative) for case in included)
    precision, recall = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    references = [case for case in included if case.mutation == "no_injected_mutation"]
    return LineSummary(
        configurations=len(included),
        unique_devices=len({(case.source_id, case.device_id) for case in included}),
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=sum(case.true_negative for case in included),
        precision=precision,
        recall=recall,
        f1=2 * precision * recall / (precision + recall) if precision + recall else 0,
        false_positives_per_configuration=fp / max(len(included), 1),
        reference_configurations=len(references),
        reference_configurations_with_alerts=sum(bool(case.false_positive) for case in references),
        excluded_deletion_only=len(cases) - len(included),
        unscorable_lines=sum(case.unscorable_lines for case in included),
    )


def vary_text(text: str, vendor: Vendor | None, variant: Variant) -> str:
    """Apply the same harmless formatting/context change to parent and child."""
    if variant == "original":
        return text
    if variant == "leading_blank":
        return "\n\n" + text
    if variant == "comment_context":
        comment = "!" if vendor is Vendor.CISCO else "#"
        return f"{comment} diagnostic context\n" + text
    if variant == "crlf":
        return text.replace("\r\n", "\n").replace("\n", "\r\n")
    raise ValueError("unknown diagnostic variant")


def evaluate_localization(result: LineResult, splits: DatasetSplitResult) -> LineDiagnostics:
    """Inspect fixed-model errors on known validation and paired format variants."""
    report = LineReport.model_validate(result.report.model_dump())
    if _encoder_hash(result.pretrained.model) != report.encoder_sha256:
        raise ValueError("encoder differs from localization report")
    rows, _ = prepare_examples(splits, report.mutation_types, report.policy)
    if (
        _fingerprint(rows[DatasetSplit.TRAIN]) != report.train_fingerprint
        or _fingerprint(rows[DatasetSplit.VALIDATION]) != report.validation_fingerprint
    ):
        raise ValueError("diagnostic corpus differs from localization training")
    validation = rows[DatasetSplit.VALIDATION]
    if len(validation) * len(VARIANTS) > report.policy.max_examples:
        raise ValueError("diagnostic example budget exceeded")
    originals = {
        row.parent_sha256: row.record.sanitized_text for row in validation if row.label == 0
    }
    cases = []
    total_lines = 0
    for row in validation:
        for variant in VARIANTS:
            text = vary_text(row.record.sanitized_text, row.record.vendor_hint, variant)
            parent = vary_text(originals[row.parent_sha256], row.record.vendor_hint, variant)
            targets = line_targets(parent, text)
            deletion_only = bool(row.label and not targets.changed_lines)
            total_lines += len(text.splitlines())
            if total_lines > report.policy.max_lines:
                raise ValueError("diagnostic line budget exceeded")
            record = row.record.model_copy(
                update={"sanitized_text": text, "sanitized_sha256": digest(text)}
            )
            predictions = () if deletion_only else predict_lines(result, record)
            truth = set(targets.changed_lines)
            ignored = set(targets.ignored_lines)
            tp: list[int] = []
            fp: list[int] = []
            fn: list[int] = []
            tn, unscorable = 0, 0
            for prediction in predictions:
                line = prediction.line_number
                if line in ignored:
                    continue
                if prediction.predicted_changed is None:
                    if line in truth:
                        raise ValueError("positive diagnostic line is unscorable")
                    unscorable += 1
                elif prediction.predicted_changed:
                    (tp if line in truth else fp).append(line)
                elif line in truth:
                    fn.append(line)
                else:
                    tn += 1
            cases.append(
                LineCase(
                    source_id=record.source_id,
                    record_id=record.record_id,
                    device_id=record.device_id,
                    source_sha256=record.sanitized_sha256,
                    vendor=str(record.vendor_hint),
                    mutation=report.mutation_types[row.label - 1].value
                    if row.label
                    else "no_injected_mutation",
                    variant=variant,
                    true_positive=tuple(tp),
                    false_positive=tuple(fp),
                    false_negative=tuple(fn),
                    true_negative=tn,
                    ignored_lines=len(ignored),
                    unscorable_lines=unscorable,
                    deletion_only=deletion_only,
                )
            )
    # Include head values as well as encoder identity, binding diagnostics to this exact model.
    checksum = hashlib.sha256(report.encoder_sha256.encode())
    checksum.update(result.pretrained.tokenizer.tokenizer_sha256.encode())
    for name, value in sorted(result.head.state_dict().items()):
        checksum.update(name.encode())
        checksum.update(str(tuple(value.shape)).encode())
        checksum.update(str(value.dtype).encode())
        checksum.update(value.detach().cpu().contiguous().numpy().tobytes())
    model_hash = checksum.hexdigest()
    return LineDiagnostics(
        model_sha256=model_hash,
        validation_fingerprint=report.validation_fingerprint,
        threshold=report.threshold,
        summary=summarize(tuple(cases)),
        by_vendor={
            key: summarize(tuple(case for case in cases if case.vendor == key))
            for key in sorted({case.vendor for case in cases})
        },
        by_mutation={
            key: summarize(tuple(case for case in cases if case.mutation == key))
            for key in sorted({case.mutation for case in cases})
        },
        by_variant={
            key: summarize(tuple(case for case in cases if case.variant == key)) for key in VARIANTS
        },
        cases=tuple(cases),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    result = load_localizer(args.model)
    report = evaluate_localization(result, classification_fixtures())
    with args.output.open("x", encoding="utf-8") as target:
        target.write(report.model_dump_json(indent=2) + "\n")
    print(report.summary.model_dump_json(indent=2))
    print("Paired validation diagnostics, not independent networks or real anomaly quality.")


if __name__ == "__main__":
    main()
