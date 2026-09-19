"""Train-only character TF-IDF line baseline for synthetic mutation localization."""

from __future__ import annotations

import argparse
import json
import warnings
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from ml.datasets import (
    DatasetSplit,
    DatasetSplitResult,
    ImportedDatasetRecord,
    deduplicate_dataset,
    split_deduplicated_dataset,
)
from ml.datasets.laboratory import LAB_VERSION, laboratory_records
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.training.classification import ProbeExample, ProbePolicy, _fingerprint, prepare_examples
from ml.training.localization import LineScore, line_targets, load_localizer
from ml.training.localization_evaluation import (
    VARIANTS,
    LineCase,
    evaluate_localization,
    summarize,
    vary_text,
)

LEXICAL_VERSION = "lexical-lines-0.1.0"
MAX_LINES = 50000


@dataclass
class LexicalLocalizer:
    pipeline: Pipeline
    train_fingerprint: str
    vocabulary_sha256: str
    model_sha256: str
    train_lines: int
    train_positive_lines: int


def fit_lexical_localizer(rows: list[ProbeExample]) -> LexicalLocalizer:
    """Fit vocabulary, IDF and classifier on supplied training rows only."""
    originals = {row.parent_sha256: row.record.sanitized_text for row in rows if not row.label}
    texts: list[str] = []
    labels: list[int] = []
    total_lines = 0
    for row in rows:
        if digest(row.record.sanitized_text) != row.record.sanitized_sha256:
            raise ValueError("lexical training checksum mismatch")
        targets = line_targets(originals[row.parent_sha256], row.record.sanitized_text)
        if row.label and not targets.changed_lines:
            continue
        lines = row.record.sanitized_text.splitlines()
        total_lines += len(lines)
        if total_lines > MAX_LINES:
            raise ValueError("lexical training line budget exceeded")
        for number, text in enumerate(lines, 1):
            if number in targets.ignored_lines:
                continue
            if not text.strip():
                if number in targets.changed_lines:
                    raise ValueError("positive lexical line is unscorable")
                continue
            texts.append(text)
            labels.append(int(number in targets.changed_lines))
    if set(labels) != {0, 1}:
        raise ValueError("lexical training requires both line classes")
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    lowercase=False,
                    sublinear_tf=True,
                    max_features=10000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=17,
                    max_iter=1000,
                ),
            ),
        ]
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        pipeline.fit(texts, labels)
    vocabulary = {
        key: int(value) for key, value in pipeline.named_steps["tfidf"].vocabulary_.items()
    }
    model_hash = digest(
        json.dumps(
            {
                "vocabulary": vocabulary,
                "idf": pipeline.named_steps["tfidf"].idf_.tolist(),
                "coefficients": pipeline.named_steps["classifier"].coef_.tolist(),
                "intercept": pipeline.named_steps["classifier"].intercept_.tolist(),
                "classes": pipeline.named_steps["classifier"].classes_.tolist(),
            },
            sort_keys=True,
            allow_nan=False,
        )
    )
    return LexicalLocalizer(
        pipeline,
        _fingerprint(rows),
        digest(json.dumps(vocabulary, sort_keys=True)),
        model_hash,
        len(labels),
        sum(labels),
    )


def predict_lexical_lines(
    model: LexicalLocalizer, record: ImportedDatasetRecord
) -> tuple[LineScore, ...]:
    if digest(record.sanitized_text) != record.sanitized_sha256:
        raise ValueError("lexical inference checksum mismatch")
    lines = record.sanitized_text.splitlines()
    if not lines or len(lines) > MAX_LINES or len(record.sanitized_text.encode()) > 1024 * 1024:
        raise ValueError("lexical inference input exceeds budget or is empty")
    indices = [index for index, line in enumerate(lines) if line.strip()]
    scores = {}
    if indices:
        values = model.pipeline.predict_proba([lines[index] for index in indices])
        scores = {index: float(value[1]) for index, value in zip(indices, values, strict=True)}
    return tuple(
        LineScore(
            source_sha256=record.sanitized_sha256,
            line_number=index + 1,
            changed_score=scores.get(index),
            predicted_changed=scores[index] > 0.5 if index in scores else None,
        )
        for index in range(len(lines))
    )


def lexical_diagnostics(
    model: LexicalLocalizer,
    rows: list[ProbeExample],
    types: tuple[MutationType, ...],
) -> dict[str, object]:
    originals = {row.parent_sha256: row.record.sanitized_text for row in rows if not row.label}
    cases = []
    line_budget = 0
    for row in rows:
        for variant in VARIANTS:
            text = vary_text(row.record.sanitized_text, row.record.vendor_hint, variant)
            original = vary_text(originals[row.parent_sha256], row.record.vendor_hint, variant)
            target = line_targets(original, text)
            deletion_only = bool(row.label and not target.changed_lines)
            line_budget += len(text.splitlines())
            if line_budget > MAX_LINES:
                raise ValueError("lexical diagnostic line budget exceeded")
            record = row.record.model_copy(
                update={"sanitized_text": text, "sanitized_sha256": digest(text)}
            )
            predictions = () if deletion_only else predict_lexical_lines(model, record)
            tp: list[int] = []
            fp: list[int] = []
            fn: list[int] = []
            tn, unscorable = 0, 0
            for item in predictions:
                line = item.line_number
                if line in target.ignored_lines:
                    continue
                positive = line in target.changed_lines
                if item.changed_score is None:
                    if positive:
                        raise ValueError("positive lexical line is unscorable")
                    unscorable += 1
                elif item.predicted_changed:
                    if positive:
                        tp.append(line)
                    else:
                        fp.append(line)
                elif positive:
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
                    mutation=types[row.label - 1].value if row.label else "no_injected_mutation",
                    variant=variant,
                    true_positive=tuple(tp),
                    false_positive=tuple(fp),
                    false_negative=tuple(fn),
                    true_negative=tn,
                    ignored_lines=len(target.ignored_lines),
                    unscorable_lines=unscorable,
                    deletion_only=deletion_only,
                )
            )
    return {
        "version": LEXICAL_VERSION,
        "sklearn_version": version("scikit-learn"),
        "synthetic_only": True,
        "independent_test": False,
        "calibrated_probability": False,
        "train_fingerprint": model.train_fingerprint,
        "validation_fingerprint": _fingerprint(rows),
        "vocabulary_sha256": model.vocabulary_sha256,
        "model_sha256": model.model_sha256,
        "train_lines": model.train_lines,
        "train_positive_lines": model.train_positive_lines,
        "threshold": 0.5,
        "feature_policy": {
            "analyzer": "char_wb",
            "ngram_range": [2, 5],
            "max_features": 10000,
            "lowercase": False,
            "sublinear_tf": True,
        },
        "classifier_policy": {
            "C": 1.0,
            "solver": "liblinear",
            "class_weight": "balanced",
            "random_state": 17,
            "max_iter": 1000,
        },
        "summary": summarize(tuple(cases)).model_dump(),
        "by_variant": {
            key: summarize(tuple(case for case in cases if case.variant == key)).model_dump()
            for key in VARIANTS
        },
        "by_vendor": {
            key: summarize(tuple(case for case in cases if case.vendor == key)).model_dump()
            for key in sorted({case.vendor for case in cases})
        },
        "cases": [case.model_dump() for case in cases],
    }


def train_lexical_baseline(
    splits: DatasetSplitResult,
) -> tuple[LexicalLocalizer, dict[str, object]]:
    types = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    rows, _ = prepare_examples(splits, types, ProbePolicy())
    model = fit_lexical_localizer(rows[DatasetSplit.TRAIN])
    return model, lexical_diagnostics(model, rows[DatasetSplit.VALIDATION], types)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transformer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    _, lexical = train_lexical_baseline(splits)
    transformer = evaluate_localization(load_localizer(args.transformer), splits)
    if lexical["validation_fingerprint"] != transformer.validation_fingerprint:
        raise ValueError("comparison requires identical validation examples and labels")
    report = {"corpus": LAB_VERSION, "lexical": lexical, "transformer": transformer.model_dump()}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
    print(json.dumps(lexical["by_variant"], indent=2))
    print("Synthetic validation comparison only; no production model promotion.")


if __name__ == "__main__":
    main()
