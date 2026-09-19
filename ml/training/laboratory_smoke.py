"""Train and validate on authored lab scenarios, without evaluating test scores."""

from __future__ import annotations

import argparse
from pathlib import Path

from ml.datasets import deduplicate_dataset, split_deduplicated_dataset
from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.localization import save_localizer, train_line_localizer
from ml.training.localization_evaluation import evaluate_localization
from ml.training.transformer import train_masked_language_model


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=512, context_length=64)
    )
    pretrained = train_masked_language_model(splits, tokenizer)
    model = train_line_localizer(
        splits, pretrained, (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    )
    diagnostics = evaluate_localization(model, splits)
    args.output.mkdir(exist_ok=False)
    (args.output / ".incomplete").write_text("bundle writing\n", encoding="utf-8")
    save_localizer(model, args.output / "model")
    (args.output / "validation.json").write_text(
        diagnostics.model_dump_json(indent=2), encoding="utf-8"
    )
    (args.output / "splits.json").write_text(splits.model_dump_json(), encoding="utf-8")
    (args.output / ".incomplete").unlink()
    print("Synthetic scenario validation; not real network generalization or device acceptance.")
    print(diagnostics.by_variant["original"].model_dump_json(indent=2))
    print("Vendor summaries include paired diagnostic variants:")
    for vendor, summary in diagnostics.by_vendor.items():
        print(vendor, summary.model_dump_json())


if __name__ == "__main__":
    main()
