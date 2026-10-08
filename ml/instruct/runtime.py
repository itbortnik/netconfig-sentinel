"""Opt-in pinned local Qwen generation; schema/citations remain a separate boundary."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, replace
from importlib.metadata import version
from pathlib import Path
from threading import Lock
from typing import Any, Literal, cast

from app.explanation.provider import (
    SYSTEM_INSTRUCTIONS,
    DraftAnswer,
    InvalidProviderAnswer,
    ProviderPrompt,
)
from pydantic import BaseModel, ConfigDict, Field
from tokenizers import Tokenizer

from ml.evaluation.contracts import Digest
from ml.instruct.framing import END, START, GenerationLimits, frame_prompt, generated_answer
from ml.instruct.source import MODEL_ID, REVISION, inventory_sha256, verify_model_files


class InstructIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    model_id: Literal["Qwen/Qwen3-4B-Instruct-2507"] = MODEL_ID
    revision: Literal["cdbee75f17c01a7cc42f958dc650907174af0554"] = REVISION
    source_inventory_sha256: Digest
    publisher_license_declaration: Literal["Apache-2.0"] = "Apache-2.0"
    external_training_exposure: Literal["unknown"] = "unknown"
    parameter_count: int = Field(ge=3000000000, le=8000000000, strict=True)
    device_name: str = Field(min_length=1, max_length=128)
    dtype: Literal["bfloat16"] = "bfloat16"
    attention_implementation: Literal["sdpa"] = "sdpa"
    pipeline_version: Literal["qwen3-fixed-roles-greedy-0.1.0"] = "qwen3-fixed-roles-greedy-0.1.0"
    runtime_versions: tuple[str, ...]
    automatic_activation: Literal[False] = False
    production_quality_proven: Literal[False] = False


@dataclass(frozen=True)
class GenerationObservation:
    prompt_tokens: int
    generated_tokens: int
    seconds: float
    context_sha256: str
    completed: bool = True
    rejection: Literal["deadline", "incomplete_or_controls"] | None = None


def _load_gpu_model(root: Path) -> tuple[Any, Tokenizer, InstructIdentity]:
    """Only the native reviewed architecture; local safetensors, no Auto/remote code."""
    import torch
    from transformers import Qwen3Config, Qwen3ForCausalLM

    if (
        version("torch").split("+")[0] != "2.14.0"
        or version("transformers") != "5.19.0"
        or version("tokenizers") != "0.23.2"
        or version("safetensors") != "0.8.0"
        or not torch.cuda.is_available()
        or not torch.cuda.is_bf16_supported()
        or torch.cuda.mem_get_info(0)[0] < 10 * 1024**3
    ):
        raise ValueError("instruct runtime or free GPU memory is unsupported")
    tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
    tokenizer.no_padding()
    tokenizer.no_truncation()
    tokenizer.encode_special_tokens = True
    if [
        tokenizer.token_to_id(name)
        for name in (
            "<|endoftext|>",
            "<|im_start|>",
            "<|im_end|>",
        )
    ] != [151643, START, END]:
        raise ValueError("instruct tokenizer controls differ")
    configuration = Qwen3Config.from_dict(json.loads((root / "config.json").read_bytes()))
    # Upstream annotation omits its documented output_loading_info tuple variant.
    model, loading = cast(Any, Qwen3ForCausalLM).from_pretrained(
        str(root),
        config=configuration,
        local_files_only=True,
        use_safetensors=True,
        weights_only=True,
        dtype=torch.bfloat16,
        attn_implementation="sdpa",
        output_loading_info=True,
    )
    if any(
        loading.get(key)
        for key in (
            "missing_keys",
            "unexpected_keys",
            "mismatched_keys",
            "error_msgs",
        )
    ):
        raise ValueError("instruct tensor layout differs")
    model.to("cuda:0")
    torch.nn.Module.train(model, False)
    torch.nn.Module.requires_grad_(model, False)
    if any(
        parameter.device.type != "cuda"
        or parameter.dtype != torch.bfloat16
        or not bool(torch.isfinite(parameter).all())
        for parameter in model.parameters()
    ):
        raise ValueError("instruct tensors are unsupported")
    identity = InstructIdentity(
        source_inventory_sha256=inventory_sha256(),
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        device_name=torch.cuda.get_device_name(0),
        runtime_versions=tuple(
            f"{name}={version(name)}"
            for name in (
                "torch",
                "transformers",
                "tokenizers",
                "safetensors",
                "numpy",
            )
        ),
    )
    return model, tokenizer, identity


def _generate(
    model: Any,
    ids: list[int],
    limits: GenerationLimits,
) -> tuple[list[int], float]:
    import torch
    from transformers import GenerationConfig, StoppingCriteria, StoppingCriteriaList

    if any(module.training for module in model.modules()) or any(
        parameter.requires_grad or parameter.grad is not None for parameter in model.parameters()
    ):
        raise ValueError("instruct model is not frozen")
    started = time.monotonic()

    class Deadline(StoppingCriteria):
        def __call__(self, input_ids: Any, scores: Any, **kwargs: Any) -> bool:
            return time.monotonic() - started >= limits.timeout_seconds

    configuration = cast(Any, GenerationConfig)(
        do_sample=False,
        num_beams=1,
        max_new_tokens=limits.max_new_tokens,
        eos_token_id=[END, 151643],
        pad_token_id=151643,
        bos_token_id=151643,
        use_cache=True,
        return_dict_in_generate=False,
        temperature=None,
        top_k=None,
        top_p=None,
    )
    tensor = torch.tensor([ids], dtype=torch.long, device="cuda:0")
    with torch.inference_mode():
        result = model.generate(
            tensor,
            attention_mask=torch.ones_like(tensor),
            generation_config=configuration,
            stopping_criteria=StoppingCriteriaList([Deadline()]),
            logits_to_keep=1,
        )
    # CPU transfer synchronizes before measuring and before returning any answer.
    generated: list[int] = result[0, len(ids) :].tolist()
    return generated, time.monotonic() - started


class LocalInstructProvider:
    """Library-only explicit invocation. No service, download, credentials or API activation.

    Step deadline is not a hard GPU-kernel cancellation guarantee. A caller needing a hard
    process deadline must own an isolated worker and kill/reap it; see the owned diagnostic.
    """

    def __init__(
        self,
        root: Path,
        *,
        expected_inventory_sha256: str,
        allow_local_context: bool,
        allow_patch_draft: bool = False,
        allow_candidate_review: bool = False,
        limits: GenerationLimits | None = None,
    ) -> None:
        if allow_local_context is not True:
            raise ValueError("explicit local context permission is required")
        if type(allow_patch_draft) is not bool:
            raise ValueError("unsupported instruct patch permission")
        self._patch_generation_enabled = allow_patch_draft
        if type(allow_candidate_review) is not bool:
            raise ValueError("unsupported instruct candidate review permission")
        self._candidate_review_enabled = allow_candidate_review
        limits = limits or GenerationLimits()
        self._limits = GenerationLimits(
            limits.max_prompt_tokens,
            limits.max_new_tokens,
            limits.timeout_seconds,
        )
        verify_model_files(root, expected_inventory_sha256=expected_inventory_sha256)
        try:
            self._model, self._tokenizer, self.identity = _load_gpu_model(root)
            if self.identity.source_inventory_sha256 != expected_inventory_sha256:
                raise ValueError("loaded instruct identity differs from selected source")
        except Exception:
            raise ValueError("Local instruct runtime is unavailable.") from None
        self._lock = Lock()
        self.last_generation: GenerationObservation | None = None

    @property
    def limits(self) -> GenerationLimits:
        return self._limits

    @property
    def patch_generation_enabled(self) -> bool:
        return self._patch_generation_enabled

    @property
    def candidate_review_enabled(self) -> bool:
        return self._candidate_review_enabled

    def generate(self, prompt: ProviderPrompt) -> bytes:
        if not self._lock.acquire(blocking=False):
            raise InvalidProviderAnswer("Local instruct generation is unavailable.")
        self.last_generation = None
        try:
            contracts = {
                (SYSTEM_INSTRUCTIONS, json.dumps(DraftAnswer.model_json_schema(), sort_keys=True))
            }
            if self._patch_generation_enabled:
                from app.explanation.patch_provider import PATCH_INSTRUCTIONS, PatchDraftAnswer

                contracts.add(
                    (
                        PATCH_INSTRUCTIONS,
                        json.dumps(PatchDraftAnswer.model_json_schema(), sort_keys=True),
                    )
                )
            if self._candidate_review_enabled:
                from app.explanation.candidate_review import REVIEW_INSTRUCTIONS, ReviewDraftAnswer

                contracts.add(
                    (
                        REVIEW_INSTRUCTIONS,
                        json.dumps(ReviewDraftAnswer.model_json_schema(), sort_keys=True),
                    )
                )
            if (prompt.instructions, prompt.answer_schema_json) not in contracts:
                raise ValueError("instruct instructions or answer schema differs")
            ids = frame_prompt(self._tokenizer, prompt, self._limits)
            generated, seconds = _generate(self._model, ids, self._limits)
            if not math.isfinite(seconds) or seconds < 0:
                raise ValueError("invalid instruct generation measurement")
            if seconds > self._limits.timeout_seconds:
                self.last_generation = GenerationObservation(
                    len(ids),
                    len(generated),
                    seconds,
                    prompt.context_sha256,
                    completed=False,
                    rejection="deadline",
                )
                raise ValueError("instruct generation exceeded deadline")
            self.last_generation = GenerationObservation(
                len(ids),
                len(generated),
                seconds,
                prompt.context_sha256,
                completed=False,
                rejection="incomplete_or_controls",
            )
            answer = generated_answer(self._tokenizer, generated, self._limits)
            self.last_generation = replace(self.last_generation, completed=True, rejection=None)
            return answer
        except Exception:
            raise InvalidProviderAnswer("Local instruct generation is unavailable.") from None
        finally:
            self._lock.release()
