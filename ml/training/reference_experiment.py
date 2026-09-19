"""Paired fixed-budget baseline versus train-only reference context augmentation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.mutation import MutationType
from ml.training.checkpoint import load_checkpoint
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import LinePolicy, save_localizer, train_line_localizer
from ml.training.localization_evaluation import evaluate_localization


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encoder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    pretrained = load_checkpoint(args.encoder)
    splits = classification_fixtures()
    args.output.mkdir(exist_ok=False)
    (args.output / ".incomplete").write_text("experiment running\n", encoding="utf-8")
    summaries = {}
    for label, policy in (
        ("baseline", LinePolicy(epochs=20, feature_version="stable-lines-0.1.0")),
        (
            "augmented",
            LinePolicy(
                epochs=20,
                feature_version="stable-lines-0.1.0",
                reference_augmentation="management-comments-0.1.0",
            ),
        ),
    ):
        model = train_line_localizer(
            splits,
            pretrained,
            (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED),
            policy=policy,
        )
        save_localizer(model, args.output / label)
        diagnostics = evaluate_localization(model, splits)
        (args.output / f"{label}-diagnostics.json").write_text(
            diagnostics.model_dump_json(indent=2), encoding="utf-8"
        )
        summaries[label] = {
            "training_lines": model.report.train_lines,
            "positive_training_lines": model.report.train_positive_lines,
            "added_reference_examples": model.report.augmented_reference_examples,
            "positive_weight": model.report.positive_weight,
            "effective_train_fingerprint": model.report.effective_train_fingerprint,
            "threshold": model.report.threshold,
            "original_validation": diagnostics.by_variant["original"].model_dump(),
            "paired_diagnostics": diagnostics.summary.model_dump(),
        }
    comparison = {
        "synthetic_only": True,
        "independent_test": False,
        "default_changed": False,
        "runs": summaries,
    }
    text = json.dumps(comparison, indent=2)
    (args.output / "comparison.json").write_text(text, encoding="utf-8")
    (args.output / ".incomplete").unlink()
    print(text)


if __name__ == "__main__":
    main()
