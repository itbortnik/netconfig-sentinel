"""Measured authored joint Stage A -> B demonstration, not independent model quality."""

from __future__ import annotations

import argparse
from pathlib import Path

from ml.evaluation.cli import write_report
from ml.evaluation.metrics import evaluate
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.mutation import MutationType
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    FineTunePolicy,
    load_multitask,
    predict_multitask,
    save_multitask,
    train_multitask,
)
from ml.training.pretraining import (
    PretrainingPolicy,
    load_pretraining,
    pretraining_identity,
    train_configuration_objectives,
)
from ml.training.pretraining_data import PretrainingWeights
from ml.training.pretraining_smoke import pretraining_fixtures
from ml.training.transformer import EncoderPolicy


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-model", type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("choose a new output directory")
    try:
        splits, pairs = pretraining_fixtures()
        if args.source_model is not None:
            source = load_pretraining(args.source_model)
        else:
            tokenizer = train_config_tokenizer(
                splits, policy=TokenizerPolicy(vocab_size=512, context_length=128)
            )
            source = train_configuration_objectives(
                splits,
                tokenizer,
                semantic_pairs=pairs,
                weights=PretrainingWeights(cross_vendor=0.1),
                encoder_policy=EncoderPolicy(
                    hidden_size=32, heads=4, layers=2, feedforward_size=64
                ),
                training_policy=PretrainingPolicy(epochs=10),
            )
        source_identity = pretraining_identity(source)
        examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
        result = train_multitask(
            splits,
            source,
            examples,
            semantic_pairs=pairs,
            head_policy=HeadPolicy(classes=("telnet_enabled",), max_examples=128),
            training_policy=FineTunePolicy(epochs=20),
            loss_weights=LossWeights(severity=0),
        )
        if pretraining_identity(source) != source_identity:
            raise ValueError("source model changed during transfer")
        save_multitask(result, args.output)
        restored = load_multitask(args.output)
        if predict_multitask(result, examples[0].record) != predict_multitask(
            restored, examples[0].record
        ):
            raise ValueError("saved transfer prediction differs")
        batch = build_multitask_validation(restored, splits, examples)
        report = evaluate(batch)
        # Separate metrics from the exact model directory: inventory checks stay meaningful.
        with (args.output.parent / (args.output.name + "-training.json")).open(
            "x", encoding="utf-8"
        ) as stream:
            stream.write(result.report.model_dump_json(indent=2) + "\n")
        write_report(
            report,
            args.output.parent / (args.output.name + "-validation.json"),
            args.output.parent / (args.output.name + "-reliability.svg"),
        )
    except (OSError, ValueError, RuntimeError):
        parser.exit(
            2, "Transfer failed: check trusted source/corpus/labels and unused output paths.\n"
        )
    print(
        "Authored joint Stage A -> B and saved prediction verified; severity disabled, "
        "test untouched, no external foundation model or real quality claim."
    )
    print(
        f"train={result.report.train_examples}, validation={result.report.validation_examples}, "
        f"trainable={result.report.trainable_parameters}, source_sha256={source_identity}"
    )


if __name__ == "__main__":
    main()
