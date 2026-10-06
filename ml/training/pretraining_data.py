"""Source-bound, partition-local objectives, without manufactured semantic truth."""

from __future__ import annotations

import ipaddress
import json
import random
import re
from bisect import bisect_left
from dataclasses import dataclass
from typing import Literal

from app.domain import Vendor
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from tokenizers import Tokenizer

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.blocks import ConfigurationBlock, digest, segment_configuration
from ml.preprocessing.tokenization import (
    TokenizerArtifact,
    TokenWindow,
    _validate_split_entities,
    encode_block,
)
from ml.training.masking import IGNORE_LABEL, MaskedWindow, mask_window

TASKS = ("token", "command", "parameter", "replaced_line", "same_device", "cross_vendor")
DATA_VERSION = "config-pretraining-data-0.1.0"


class PretrainingWeights(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    token: float = Field(default=1, ge=0, le=100)
    command: float = Field(default=1, ge=0, le=100)
    parameter: float = Field(default=1, ge=0, le=100)
    replaced_line: float = Field(default=1, ge=0, le=100)
    same_device: float = Field(default=1, ge=0, le=100)
    cross_vendor: float = Field(default=0, ge=0, le=100)

    @model_validator(mode="after")
    def nonempty(self) -> PretrainingWeights:
        if not any(self.model_dump().values()):
            raise ValueError("at least one pretraining objective must be enabled")
        return self


class SemanticPair(BaseModel):
    """Operator-supplied semantic labels; metadata does not attest their truth."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    left_sha256: Digest
    right_sha256: Digest
    equivalent: StrictBool
    scope: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    review_sha256: Digest
    origin: Literal["synthetic", "laboratory", "real_confirmed"]

    @model_validator(mode="after")
    def distinct(self) -> SemanticPair:
        if self.left_sha256 == self.right_sha256:
            raise ValueError("semantic pair must contain distinct configurations")
        return self


@dataclass(frozen=True)
class LineExample:
    window: TokenWindow
    positions: tuple[int, ...]
    replaced: bool
    parent_sha256: str
    donor_sha256: str
    source_line: int
    donor_line: int


@dataclass(frozen=True)
class PairExample:
    left: tuple[TokenWindow, ...]
    right: tuple[TokenWindow, ...]
    positive: bool
    left_sha256: str
    right_sha256: str


@dataclass(frozen=True)
class ObjectiveData:
    token: tuple[MaskedWindow, ...]
    command: tuple[MaskedWindow, ...]
    parameter: tuple[MaskedWindow, ...]
    replaced_line: tuple[LineExample, ...]
    same_device: tuple[PairExample, ...]
    cross_vendor: tuple[PairExample, ...]
    fingerprint: str
    source_fingerprint: str
    records: int
    windows: int
    semantic_scopes: tuple[str, ...]

    def counts(self) -> dict[str, int]:
        result = {
            name: sum(sum(label != IGNORE_LABEL for label in row.labels) for row in rows)
            for name, rows in (
                ("token", self.token),
                ("command", self.command),
                ("parameter", self.parameter),
            )
        }
        result.update({name: len(getattr(self, name)) for name in TASKS[3:]})
        return result


def _command_spans(text: str, vendor: Vendor) -> tuple[tuple[int, int], ...]:
    """Complete physical commands only; hierarchical JunOS is deliberately excluded."""
    spans, offset = [], 0
    for line in text.splitlines(keepends=True):
        body = line.strip()
        if (
            body
            and not body.startswith(("!", "#"))
            and not any(marker in body for marker in ("!", "#", "/*", "*/", "//"))
            and (vendor is Vendor.CISCO or body.startswith("set "))
        ):
            start = offset + len(line) - len(line.lstrip())
            spans.append((start, offset + len(line.rstrip("\r\n"))))
        offset += len(line)
    return tuple(spans)


def _parameter_spans(text: str, vendor: Vendor) -> tuple[tuple[int, int], ...]:
    """Validated IP/prefix literals and explicitly named ASN values, not arbitrary numbers."""
    spans = []
    for command_start, command_end in _command_spans(text, vendor):
        command = text[command_start:command_end]
        # Skip quoted text/descriptions: a number inside prose is not a typed parameter.
        if '"' in command or re.search(r"\b(?:description|host-name|hostname)\b", command):
            continue
        for match in re.finditer(r"(?<!\S)[^\s;]+", command):
            value = match.group()
            if "." not in value and ":" not in value:
                continue
            try:
                if "/" in value:
                    ipaddress.ip_interface(value)
                else:
                    ipaddress.ip_address(value)
            except ValueError:
                continue
            spans.append((command_start + match.start(), command_start + match.end()))
        for match in re.finditer(
            r"\b(?:router bgp|remote-as|peer-as|autonomous-system)\s+(\d+)\b", command
        ):
            if 1 <= int(match.group(1)) <= 4294967295:
                spans.append((command_start + match.start(1), command_start + match.end(1)))
    return tuple(sorted(set(spans)))


def _mask_spans(
    block: ConfigurationBlock,
    windows: tuple[TokenWindow, ...],
    tokenizer: TokenizerArtifact,
    spans: tuple[tuple[int, int], ...],
    seed: int,
) -> tuple[MaskedWindow, ...]:
    native = Tokenizer.from_str(tokenizer.tokenizer_json)
    native.encode_special_tokens = True
    encoding = native.encode(block.text, add_special_tokens=False)
    if tuple(
        token
        for window in windows
        for token, special in zip(window.input_ids, window.special_tokens_mask, strict=True)
        if not special
    ) != tuple(encoding.ids):
        raise ValueError("pretraining source offsets do not match encoded content")
    candidates: dict[int, list[tuple[int, ...]]] = {}
    starts = [left for left, _ in encoding.offsets]
    ends = [right for _, right in encoding.offsets]
    for start, end in spans:
        indices = tuple(range(bisect_left(ends, start + 1), bisect_left(starts, end)))
        if not indices:
            continue
        # Never leave a target fragment visible in another window.
        number = indices[0] // (tokenizer.policy.context_length - 2)
        window = windows[number]
        if max(indices) < window.content_token_end:
            positions = tuple(index - window.content_token_start + 1 for index in indices)
            candidates.setdefault(number, []).append(positions)
    rng = random.Random(int(digest(f"{DATA_VERSION}:{seed}:{block.block_id}"), 16))
    result = []
    for number, targets in sorted(candidates.items()):
        window = windows[number]
        chosen = rng.choice(targets)
        ids, labels = list(window.input_ids), [IGNORE_LABEL] * len(window.input_ids)
        for index in chosen:
            if window.special_tokens_mask[index] or ids[index] < 5:
                raise ValueError("source span overlaps a tokenizer control token")
            labels[index], ids[index] = ids[index], 4
        result.append(MaskedWindow(tuple(ids), window.attention_mask, tuple(labels)))
    return tuple(result)


def _line_positions(window: TokenWindow, number: int) -> tuple[int, ...]:
    return tuple(
        index
        for index, lines in enumerate(window.source_lines)
        if lines == (number,)
        and not window.special_tokens_mask[index]
        and window.attention_mask[index]
    )


def _replacements(
    rows: tuple[ImportedDatasetRecord, ...],
    blocks: dict[str, tuple[ConfigurationBlock, ...]],
    tokenizer: TokenizerArtifact,
    max_candidates: int,
) -> tuple[LineExample, ...]:
    pool: dict[tuple[Vendor | None, str, str], list[tuple[ImportedDatasetRecord, int, str]]] = {}
    candidate_count = 0
    for row in rows:
        for block in blocks[row.sanitized_sha256]:
            for number, line in enumerate(block.text.splitlines(), block.start_line):
                body = line.strip()
                if (
                    not body
                    or any(marker in body for marker in ("!", "#", "/*", "*/", "//"))
                    or "[REDACTED" in body
                ):
                    continue
                # Same command prefix/category/vendor; exclude identity and free-form prose.
                if re.search(r"\b(?:hostname|host-name|description|secret|password)\b", body):
                    continue
                prefix = " ".join(body.split()[:2])
                candidate_count += 1
                if candidate_count > max_candidates:
                    raise ValueError("replacement candidate budget exceeded")
                pool.setdefault((row.vendor_hint, block.category.value, prefix), []).append(
                    (row, number, line)
                )
    result = []
    comparisons = 0
    for candidates in pool.values():
        for parent, line_number, line in candidates:
            donor = None
            for item in candidates:
                comparisons += 1
                if comparisons > max_candidates * 32:
                    raise ValueError("replacement donor search budget exceeded")
                if (item[0].source_id, item[0].device_id) != (
                    parent.source_id,
                    parent.device_id,
                ) and item[2].strip() != line.strip():
                    donor = item
                    break
            if donor is None:
                continue
            donor_record, donor_line, donor_text = donor
            original_lines = parent.sanitized_text.splitlines(keepends=True)
            newline = (
                "\r\n"
                if original_lines[line_number - 1].endswith("\r\n")
                else ("\n" if original_lines[line_number - 1].endswith("\n") else "")
            )
            indent = line[: len(line) - len(line.lstrip())]
            original_lines[line_number - 1] = indent + donor_text.strip() + newline
            derived_text = "".join(original_lines)
            derived = parent.model_copy(
                update={"sanitized_text": derived_text, "sanitized_sha256": digest(derived_text)}
            )
            pair: list[LineExample] = []
            for record, replaced in ((parent, False), (derived, True)):
                selected = []
                for block in segment_configuration(record):
                    if block.start_line <= line_number <= block.end_line:
                        for window in encode_block(block, tokenizer):
                            positions = _line_positions(window, line_number)
                            if any(line_number in anchors for anchors in window.source_lines):
                                selected.append((window, positions))
                # A line crossing windows is not a complete line-classification example.
                if len(selected) != 1 or not selected[0][1]:
                    pair = []
                    break
                window, positions = selected[0]
                pair.append(
                    LineExample(
                        window,
                        positions,
                        replaced,
                        parent.sanitized_sha256,
                        donor_record.sanitized_sha256,
                        line_number,
                        donor_line,
                    )
                )
            result.extend(pair)
    return tuple(result)


def prepare_pretraining(
    splits: DatasetSplitResult,
    tokenizer: TokenizerArtifact,
    *,
    seed: int = 17,
    semantic_pairs: tuple[SemanticPair, ...] = (),
    max_records: int = 128,
    max_windows: int = 10000,
    max_examples: int = 20000,
) -> dict[DatasetSplit, ObjectiveData]:
    """All automatic donors/pairs stay in the original audited non-test partition."""
    if not 0 <= seed <= 2**31 - 1 or not (
        1 <= max_records <= 2048
        and 1 <= max_windows <= 100000
        and 1 <= max_examples <= 100000
        and len(semantic_pairs) <= 2048
    ):
        raise ValueError("invalid pretraining construction budgets")
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    tokenizer = TokenizerArtifact.model_validate(tokenizer.model_dump())
    _validate_split_entities(splits)
    partitions = {
        part.split: tuple(sorted(part.records, key=lambda row: (row.source_id, row.record_id)))
        for part in splits.partitions
    }
    source_fingerprints = {
        split: digest(
            json.dumps(
                [(row.source_id, row.record_id, row.sanitized_sha256) for row in rows],
                separators=(",", ":"),
            )
        )
        for split, rows in partitions.items()
    }
    if source_fingerprints[DatasetSplit.TRAIN] != tokenizer.training_fingerprint:
        raise ValueError("pretraining tokenizer belongs to a different training corpus")
    location = {
        row.sanitized_sha256: (split, row) for split, rows in partitions.items() for row in rows
    }
    if len(location) != sum(len(rows) for rows in partitions.values()):
        raise ValueError("duplicate configuration content in pretraining representatives")
    semantic: dict[DatasetSplit, list[SemanticPair]] = {
        DatasetSplit.TRAIN: [],
        DatasetSplit.VALIDATION: [],
    }
    seen = set()
    scopes = set()
    for pair in semantic_pairs:
        pair = SemanticPair.model_validate(pair.model_dump())
        left, right = location.get(pair.left_sha256), location.get(pair.right_sha256)
        if (
            left is None
            or right is None
            or left[0] != right[0]
            or left[0] is DatasetSplit.TEST
            or {left[1].vendor_hint, right[1].vendor_hint} != {Vendor.CISCO, Vendor.JUNIPER}
        ):
            raise ValueError("semantic pair needs cross-vendor sources in one non-test split")
        key = tuple(sorted((pair.left_sha256, pair.right_sha256)))
        if key in seen:
            raise ValueError("duplicate or contradictory semantic pair")
        seen.add(key)
        scopes.add(pair.scope)
        semantic[left[0]].append(pair)
    if len(scopes) > 1:
        raise ValueError("one semantic scope per contrastive training objective is required")
    result = {}
    for split in (DatasetSplit.TRAIN, DatasetSplit.VALIDATION):
        rows = partitions[split]
        if not rows or len(rows) > max_records:
            raise ValueError("pretraining record budget exceeded or empty partition")
        blocks: dict[str, tuple[ConfigurationBlock, ...]] = {}
        encoded: dict[str, list[tuple[TokenWindow, ...]]] = {}
        token: list[MaskedWindow] = []
        command: list[MaskedWindow] = []
        parameter: list[MaskedWindow] = []
        windows = 0
        for row in rows:
            if row.vendor_hint not in (Vendor.CISCO, Vendor.JUNIPER):
                raise ValueError("pretraining requires an explicit supported vendor")
            blocks[row.sanitized_sha256] = segment_configuration(row)
            encoded[row.sanitized_sha256] = []
            for block in blocks[row.sanitized_sha256]:
                batch = encode_block(block, tokenizer)
                windows += len(batch)
                if windows > max_windows:
                    raise ValueError("pretraining window budget exceeded; no truncation")
                encoded[row.sanitized_sha256].append(batch)
                token.extend(
                    mask_window(window, vocab_size=tokenizer.actual_vocab_size, seed=seed)
                    for window in batch
                )
                command.extend(
                    _mask_spans(
                        block, batch, tokenizer, _command_spans(block.text, row.vendor_hint), seed
                    )
                )
                parameter.extend(
                    _mask_spans(
                        block, batch, tokenizer, _parameter_spans(block.text, row.vendor_hint), seed
                    )
                )
        replaced = _replacements(rows, blocks, tokenizer, max_examples)
        same: list[PairExample] = []
        for row in rows:
            current = blocks[row.sanitized_sha256]
            if len(current) < 2:
                continue
            left_windows, right_windows = encoded[row.sanitized_sha256][:2]
            donor = next(
                (
                    (other, index)
                    for other in rows
                    if other.vendor_hint == row.vendor_hint
                    and (other.source_id, other.device_id) != (row.source_id, row.device_id)
                    for index, block in enumerate(blocks[other.sanitized_sha256])
                    if block.category == current[1].category and block.text != current[1].text
                ),
                None,
            )
            if donor is None:
                continue
            other, index = donor
            same.extend(
                (
                    PairExample(
                        left_windows,
                        right_windows,
                        True,
                        row.sanitized_sha256,
                        row.sanitized_sha256,
                    ),
                    PairExample(
                        left_windows,
                        encoded[other.sanitized_sha256][index],
                        False,
                        row.sanitized_sha256,
                        other.sanitized_sha256,
                    ),
                )
            )
        cross = tuple(
            PairExample(
                tuple(window for block in encoded[pair.left_sha256] for window in block),
                tuple(window for block in encoded[pair.right_sha256] for window in block),
                pair.equivalent,
                pair.left_sha256,
                pair.right_sha256,
            )
            for pair in semantic[split]
        )
        if max(len(token), len(command), len(parameter), len(replaced), len(same), len(cross)) > (
            max_examples
        ):
            raise ValueError("pretraining objective example budget exceeded")
        fingerprint = canonical_hash(
            {
                "version": DATA_VERSION,
                "seed": seed,
                "source": source_fingerprints[split],
                "tokenizer": tokenizer.tokenizer_sha256,
                "semantic_pairs": [pair.model_dump(mode="json") for pair in semantic[split]],
                "replaced": [
                    (
                        row.parent_sha256,
                        row.donor_sha256,
                        row.source_line,
                        row.donor_line,
                        row.replaced,
                    )
                    for row in replaced
                ],
                "same": [(row.left_sha256, row.right_sha256, row.positive) for row in same],
            }
        )
        result[split] = ObjectiveData(
            tuple(token),
            tuple(command),
            tuple(parameter),
            replaced,
            tuple(same),
            cross,
            fingerprint,
            source_fingerprints[split],
            len(rows),
            windows,
            tuple(sorted(scopes)),
        )
    return result
