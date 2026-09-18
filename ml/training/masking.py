"""Deterministic BERT-style masking of content tokens only."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from ml.preprocessing.tokenization import TokenWindow

MASKING_VERSION = "config-mlm-masking-0.1.0"
IGNORE_LABEL = -100


@dataclass(frozen=True)
class MaskedWindow:
    input_ids: tuple[int, ...]
    attention_mask: tuple[int, ...]
    labels: tuple[int, ...]


def mask_window(
    window: TokenWindow,
    *,
    vocab_size: int,
    seed: int,
    epoch: int = 0,
    probability: float = 0.15,
) -> MaskedWindow:
    """Select 15% of content; replace 80% by MASK, 10% randomly, 10% unchanged."""
    if not 0 < probability <= 1 or seed < 0 or epoch < 0 or vocab_size <= 5:
        raise ValueError("invalid masking parameters")
    window = TokenWindow.model_validate(window.model_dump())
    if any(token < 0 or token >= vocab_size for token in window.input_ids):
        raise ValueError("token ID outside vocabulary")
    if any(value not in (0, 1) for value in (*window.attention_mask, *window.special_tokens_mask)):
        raise ValueError("window masks must be binary")
    candidates = [
        index
        for index, (token, attention, special) in enumerate(
            zip(
                window.input_ids,
                window.attention_mask,
                window.special_tokens_mask,
                strict=True,
            )
        )
        if attention and not special and token >= 5
    ]
    if not candidates:
        raise ValueError("window has no maskable content")
    payload = (
        f"{MASKING_VERSION}\0{seed}\0{epoch}\0{window.block_id}\0"
        f"{window.window_index}\0{window.tokenizer_sha256}"
    )
    rng = random.Random(int.from_bytes(hashlib.sha256(payload.encode()).digest(), "big"))
    selected = rng.sample(candidates, max(1, round(len(candidates) * probability)))
    ids = list(window.input_ids)
    labels = [IGNORE_LABEL] * len(ids)
    for index in selected:
        labels[index] = ids[index]
        choice = rng.random()
        if choice < 0.8:
            ids[index] = 4
        elif choice < 0.9:
            ids[index] = rng.randrange(5, vocab_size)
    return MaskedWindow(tuple(ids), window.attention_mask, tuple(labels))
