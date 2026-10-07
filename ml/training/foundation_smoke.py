"""Actual external frozen encoder -> configuration adapter training on owned fixtures only."""

from __future__ import annotations

import argparse
from pathlib import Path

from app.explanation.vector_index import RetrievalUnavailable

from ml.evaluation.cli import write_report
from ml.evaluation.foundation_validation import build_foundation_validation
from ml.evaluation.metrics import evaluate
from ml.mutation import MutationType
from ml.training.foundation import ConfigFoundation
from ml.training.foundation_transfer import (
    load_foundation_transfer,
    predict_foundation_transfer,
    save_foundation_transfer,
    train_foundation_transfer,
)
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import FineTunePolicy
from ml.training.pretraining_smoke import pretraining_fixtures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output_paths = (
            args.output,
            args.output.parent / (args.output.name + "-training.json"),
            args.output.parent / (args.output.name + "-validation.json"),
            args.output.parent / (args.output.name + "-reliability.svg"),
        )
        if any(path.exists() or path.is_symlink() or path.is_junction() for path in output_paths):
            raise ValueError("output already exists")
        splits, _ = pretraining_fixtures()
        examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
        source = ConfigFoundation(args.source_model)
        identity = source.verify()
        result = train_foundation_transfer(
            splits,
            source,
            examples,
            head_policy=HeadPolicy(classes=("telnet_enabled",), adapter_rank=16, max_examples=128),
            training_policy=FineTunePolicy(epochs=20, learning_rate=0.001),
            loss_weights=LossWeights(severity=0),
        )
        pin = save_foundation_transfer(result, args.output)
        restored = load_foundation_transfer(
            args.output, source_root=args.source_model, expected_identity=pin
        )
        if (
            predict_foundation_transfer(result, examples[0].record)
            != (predict_foundation_transfer(restored, examples[0].record))
            or source.verify() != identity
        ):
            raise ValueError("saved foundation prediction or frozen weights differ")
        metrics = evaluate(build_foundation_validation(restored, splits, examples))
        with output_paths[1].open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(result.report.model_dump_json(indent=2) + "\n")
        write_report(metrics, output_paths[2], output_paths[3])
    except (OSError, ValueError, RuntimeError, RetrievalUnavailable):
        parser.exit(
            2, "Foundation transfer failed: check trusted source and unused local outputs.\n"
        )
    print(
        f"train={result.report.train_examples}, validation={result.report.validation_examples}, "
        f"trainable={result.report.trainable_parameters}, model_sha256={pin}"
    )
    print(
        "Owned selection diagnostics only; frozen source verified, local test untouched, "
        "external pretraining exposure unknown; not real quality or production acceptance."
    )


if __name__ == "__main__":
    main()
