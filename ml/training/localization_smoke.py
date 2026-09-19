"""Run a synthetic line-localization demonstration on tiny fixtures."""

from __future__ import annotations

import argparse
from pathlib import Path

from ml.mutation import MutationType
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import load_localizer, save_localizer, train_line_localizer
from ml.training.transformer import train_masked_language_model


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new directory")
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=512, context_length=64)
    )
    pretrained = train_masked_language_model(splits, tokenizer)
    result = train_line_localizer(
        splits, pretrained, (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    )
    save_localizer(result, args.output)
    restored = load_localizer(args.output)
    print("Synthetic changed-line validation only; no real/test quality or calibrated risk.")
    print(restored.report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
