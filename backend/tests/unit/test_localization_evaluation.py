"""Error accounting and paired validation diagnostics without model updates."""

import pytest
import torch
from app.domain import Vendor

from ml.datasets import DatasetSplit
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.localization import LinePolicy, train_line_localizer
from ml.training.localization_evaluation import (
    LineCase,
    evaluate_localization,
    summarize,
    vary_text,
)
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model


def test_error_accounting_keeps_variants_distinct_from_devices() -> None:
    case = LineCase(
        source_id="fixture",
        record_id="record-1",
        device_id="device-1",
        source_sha256="0" * 64,
        vendor="cisco",
        mutation="no_injected_mutation",
        variant="original",
        true_positive=(),
        false_positive=(2, 4),
        false_negative=(),
        true_negative=3,
        ignored_lines=0,
        unscorable_lines=0,
        deletion_only=False,
    )
    summary = summarize((case, case.model_copy(update={"variant": "crlf"})))
    assert summary.unique_devices == 1
    assert summary.configurations == 2
    assert summary.false_positive == 4
    assert summary.false_positives_per_configuration == 2
    assert summary.reference_configurations_with_alerts == 2
    assert summary.precision == summary.recall == summary.f1 == 0
    excluded = summarize((case.model_copy(update={"deletion_only": True}),))
    assert excluded.excluded_deletion_only == 1
    assert excluded.configurations == excluded.false_positive == 0


def test_variants_preserve_commands_and_shift_lines() -> None:
    text = "hostname host-000000000001\nline vty 0 4\n transport input ssh\n"
    assert vary_text(text, Vendor.CISCO, "leading_blank") == "\n\n" + text
    assert vary_text(text, Vendor.CISCO, "comment_context").startswith("! diagnostic")
    assert vary_text(text, Vendor.JUNIPER, "comment_context").startswith("# diagnostic")
    assert vary_text(text, Vendor.CISCO, "crlf").splitlines() == text.splitlines()


def test_diagnostics_are_repeatable_and_leave_test_and_weights_untouched() -> None:
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
    result = train_line_localizer(
        splits,
        pretrained,
        (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED),
        policy=LinePolicy(epochs=1),
    )
    before = {key: value.clone() for key, value in result.head.state_dict().items()}
    first = evaluate_localization(result, splits)
    assert len(first.cases) == 12
    assert first.summary.unique_devices == 1
    assert first.by_variant["original"].configurations == 3
    assert first.by_variant["original"].precision == result.report.validation_metrics[1].precision
    assert first.by_variant["original"].recall == result.report.validation_metrics[1].recall
    assert (
        first.by_variant["original"].true_positive + first.by_variant["original"].false_negative
        == 2
    )
    assert first.independent_test is False
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
                if partition.split is DatasetSplit.TEST
                else partition
                for partition in splits.partitions
            )
        }
    )
    assert first == evaluate_localization(result, changed)
    assert all(torch.equal(value, result.head.state_dict()[key]) for key, value in before.items())
    bounded = result.report.model_copy(update={"policy": LinePolicy(epochs=1, max_examples=5)})
    result.report = bounded
    with pytest.raises(ValueError, match="budget exceeded"):
        evaluate_localization(result, splits)
