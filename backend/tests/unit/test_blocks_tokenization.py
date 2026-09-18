"""Lossless source segmentation, train-only vocabulary, and window alignment."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.domain import Vendor
from tokenizers import Tokenizer

from ml.datasets import (
    DatasetSplit,
    DatasetSplitResult,
    ImportedDatasetRecord,
    deduplicate_dataset,
    split_deduplicated_dataset,
)
from ml.preprocessing.blocks import BlockCategory, digest, segment_configuration
from ml.preprocessing.tokenization import (
    TokenizerArtifact,
    TokenizerPolicy,
    encode_block,
    load_tokenizer,
    save_tokenizer,
    train_config_tokenizer,
)

SAMPLES = Path(__file__).resolve().parents[3] / "samples"


def record(text: str, index: int = 1, vendor: Vendor = Vendor.CISCO) -> ImportedDatasetRecord:
    return ImportedDatasetRecord(
        source_id="lab-source",
        record_id=f"record-{index}",
        network_id=f"network-{index}",
        site_id=f"site-{index}",
        device_id=f"device-{index}",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=index),
        vendor_hint=vendor,
        device_role="edge-router",
        raw_sha256=digest(text),
        sanitized_sha256=digest(text),
        sanitized_text=text,
        raw_byte_count=len(text.encode()),
        replacements={},
        sanitization_version="config-sanitizer-0.1.0",
    )


@pytest.fixture
def splits() -> DatasetSplitResult:
    records = [
        record(
            f"hostname host-{index:012x}\n"
            f"interface GigabitEthernet0/{index}\n"
            f" description marker{index} marker{index} marker{index}\n"
            f" ip address 198.51.{index}.1 255.255.255.0\n"
            f"router bgp {64512 + index}\n",
            index,
        )
        for index in range(1, 10)
    ]
    return split_deduplicated_dataset(records, deduplicate_dataset(records))


@pytest.mark.parametrize(
    "relative,vendor",
    [
        ("cisco_ios/edge-secure.cfg", Vendor.CISCO),
        ("cisco_ios/access-legacy.cfg", Vendor.CISCO),
        ("juniper_junos/edge-secure.conf", Vendor.JUNIPER),
        ("juniper_junos/access-set.conf", Vendor.JUNIPER),
    ],
)
def test_every_source_character_and_line_survives(relative: str, vendor: Vendor) -> None:
    text = (SAMPLES / relative).read_text(encoding="utf-8")
    blocks = segment_configuration(record(text, vendor=vendor))
    assert "".join(block.text for block in blocks) == text
    assert [
        line for block in blocks for line in range(block.start_line, block.end_line + 1)
    ] == list(range(1, len(text.splitlines()) + 1))
    categories = {block.category for block in blocks}
    assert {
        BlockCategory.MANAGEMENT,
        BlockCategory.INTERFACES,
        BlockCategory.BGP,
        BlockCategory.OSPF,
        BlockCategory.STATIC_ROUTES,
    } <= categories


def test_junos_quotes_comments_inline_and_unbalanced_braces() -> None:
    text = (
        "system { host-name host-000000000001; }\n"
        "/* comment {\n } */\n"
        'interfaces { ge-0/0/0 { description "literal } {"; } }\n'
        "protocols { bgp { group T { peer-as 65000; } } ospf { area 0; } }\n"
    )
    blocks = segment_configuration(record(text, vendor=Vendor.JUNIPER))
    assert "".join(block.text for block in blocks) == text
    assert blocks[-1].category is BlockCategory.MIXED
    with pytest.raises(ValueError, match="unfinished"):
        segment_configuration(record(text + "system {\n", vendor=Vendor.JUNIPER))


def test_unknown_commands_and_crlf_remain_exact() -> None:
    text = "hostname host-000000000001\r\nunknown-feature custom\r\n child data"
    blocks = segment_configuration(record(text))
    assert blocks[-1].category is BlockCategory.UNKNOWN
    assert "".join(block.text for block in blocks) == text
    with pytest.raises(ValueError, match="hash mismatch"):
        segment_configuration(record(text).model_copy(update={"sanitized_text": text + "x"}))


def test_training_is_repeatable_and_held_out_text_cannot_change_vocabulary(
    splits: DatasetSplitResult,
) -> None:
    policy = TokenizerPolicy(vocab_size=512, min_frequency=1)
    first = train_config_tokenizer(splits, policy=policy)
    assert first == train_config_tokenizer(splits, policy=policy)
    changed = []
    for partition in splits.partitions:
        records = partition.records
        if partition.split is not DatasetSplit.TRAIN:
            records = tuple(
                item.model_copy(
                    update={
                        "sanitized_text": item.sanitized_text + "onlyheldout " * 100,
                        "sanitized_sha256": digest(item.sanitized_text + "onlyheldout " * 100),
                    }
                )
                for item in records
            )
        changed.append(partition.model_copy(update={"records": records}))
    second = train_config_tokenizer(
        splits.model_copy(update={"partitions": tuple(changed)}), policy=policy
    )
    assert first == second
    tokenizer = Tokenizer.from_str(first.tokenizer_json)
    assert "onlyheldout" not in tokenizer.get_vocab()


def test_windows_cover_all_bytes_and_preserve_line_alignment(splits: DatasetSplitResult) -> None:
    artifact = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=16)
    )
    text = "hostname host-000000000001\ninterface Loopback0\n" + (
        " description русский [MASK] длинный текст\n" * 20
    )
    blocks = segment_configuration(record(text))
    tokenizer = Tokenizer.from_str(artifact.tokenizer_json)
    tokenizer.encode_special_tokens = True
    for block in blocks:
        windows = encode_block(block, artifact)
        ids = [
            token
            for window in windows
            for token, special in zip(
                window.input_ids,
                window.special_tokens_mask,
                strict=True,
            )
            if not special
        ]
        assert ids == tokenizer.encode(block.text, add_special_tokens=False).ids
        assert tokenizer.decode(ids) == block.text
        assert all(len(window.input_ids) == 16 for window in windows)
        assert windows[-1].content_token_end == len(ids)
        for window in windows:
            for special, locations in zip(
                window.special_tokens_mask, window.source_lines, strict=True
            ):
                assert bool(locations) != bool(special)
                assert all(block.start_line <= line <= block.end_line for line in locations)


def test_save_load_hash_validation_and_no_overwrite(
    splits: DatasetSplitResult,
    tmp_path: Path,
) -> None:
    artifact = train_config_tokenizer(splits, policy=TokenizerPolicy(vocab_size=512))
    path = tmp_path / "tokenizer.json"
    save_tokenizer(artifact, path)
    assert load_tokenizer(path) == artifact
    with pytest.raises(FileExistsError):
        save_tokenizer(artifact, path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["tokenizer_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="checksum mismatch"):
        TokenizerArtifact.model_validate(payload)


def test_training_rejects_changed_entity_metadata(splits: DatasetSplitResult) -> None:
    partitions = list(splits.partitions)
    original = partitions[0]
    changed = original.records[0].model_copy(update={"network_id": "different-network"})
    partitions[0] = original.model_copy(update={"records": (changed, *original.records[1:])})
    with pytest.raises(ValueError, match="metadata differs"):
        train_config_tokenizer(splits.model_copy(update={"partitions": tuple(partitions)}))


def test_training_order_does_not_change_model(splits: DatasetSplitResult) -> None:
    reordered = splits.model_copy(
        update={
            "partitions": tuple(
                partition.model_copy(update={"records": tuple(reversed(partition.records))})
                for partition in reversed(splits.partitions)
            )
        }
    )
    policy = TokenizerPolicy(vocab_size=512)
    assert train_config_tokenizer(splits, policy=policy) == train_config_tokenizer(
        reordered,
        policy=policy,
    )
