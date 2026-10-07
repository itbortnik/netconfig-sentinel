"""Fixed Qwen roles and bounded output; no executable publisher chat template."""

from __future__ import annotations

from dataclasses import dataclass

from app.explanation.knowledge import text_sha256
from app.explanation.provider import MAX_ANSWER_BYTES, MAX_PROMPT_BYTES, ProviderPrompt
from tokenizers import Tokenizer

START, END = 151644, 151645


@dataclass(frozen=True)
class GenerationLimits:
    max_prompt_tokens: int = 4096
    max_new_tokens: int = 1024
    timeout_seconds: int = 20

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.max_prompt_tokens, 4096),
            (self.max_new_tokens, 2048),
            (self.timeout_seconds, 20),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("unsupported instruct generation limit")


def frame_prompt(
    tokenizer: Tokenizer,
    prompt: ProviderPrompt,
    limits: GenerationLimits,
) -> list[int]:
    """Full content or rejection. Source literals must not acquire role/control identity."""
    if (
        text_sha256(prompt.context_json) != prompt.context_sha256
        or len((prompt.instructions + prompt.context_json + prompt.answer_schema_json).encode())
        > MAX_PROMPT_BYTES
        or not tokenizer.encode_special_tokens
    ):
        raise ValueError("unsupported instruct prompt")

    def ordinary(text: str) -> list[int]:
        ids = tokenizer.encode(text, add_special_tokens=False).ids
        if not ids or any(not 0 <= value < 151643 for value in ids):
            raise ValueError("instruct content contains reserved controls")
        return ids

    ids = [
        START,
        *ordinary(
            "system\n" + prompt.instructions + "\nAnswer schema:\n" + prompt.answer_schema_json
        ),
        END,
        *ordinary("\n"),
        START,
        *ordinary("user\n" + prompt.context_json),
        END,
        *ordinary("\n"),
        START,
        *ordinary("assistant\n"),
    ]
    if len(ids) > limits.max_prompt_tokens:
        raise ValueError("instruct prompt exceeds token budget")
    return ids


def generated_answer(tokenizer: Tokenizer, ids: list[int], limits: GenerationLimits) -> bytes:
    """Only a completed assistant body; no repairs, truncation, wrapper removal or retries."""
    if (
        not 2 <= len(ids) <= limits.max_new_tokens
        or ids[-1] != END
        or any(type(value) is not int or not 0 <= value < 151643 for value in ids[:-1])
    ):
        raise ValueError("instruct generation is incomplete or contains controls")
    raw = tokenizer.decode(ids[:-1], skip_special_tokens=False).encode("utf-8")
    if not raw.strip() or len(raw) > MAX_ANSWER_BYTES:
        raise ValueError("instruct answer exceeds budget")
    return raw
