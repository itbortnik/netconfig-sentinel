"""Encrypted private model-output receipts; replay never grants truth or approval."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import (
    GeneratedModelPatch,
    PatchDraftAnswer,
    PreparedPatchPrompt,
    validate_patch_answer,
)
from app.explanation.provider import _unique_keys
from app.patching.vendor_drafts import VendorDraft
from ml.inference.change_artifacts import safe_path
from ml.instruct.runtime import GenerationObservation, InstructIdentity
from ml.instruct.source import inventory_sha256

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
MAX_PLAIN_BYTES = 8 * 1024**2
MAX_ENCRYPTED_BYTES = 12 * 1024**2
_MAGIC = b"NCS-MODEL-PATCH-1\n"


class ModelPatchReceiptUnavailable(ValueError):
    """No key, ciphertext, original source, model output or path in the diagnostic."""


def _unavailable() -> ModelPatchReceiptUnavailable:
    return ModelPatchReceiptUnavailable("Model patch receipt is unavailable.")


class CompletedGeneration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    prompt_tokens: StrictInt = Field(ge=1, le=4096)
    generated_tokens: StrictInt = Field(ge=2, le=2048)
    seconds: float = Field(ge=0, le=20, allow_inf_nan=False)
    context_sha256: Digest
    completed: Literal[True]
    rejection: None

    @field_validator("completed", mode="before")
    @classmethod
    def exact_completion(cls, value: Any) -> bool:
        if value is not True:
            raise ValueError("generation is not completed")
        return True


class ModelPatchReceipt(BaseModel):
    """Confidential in-memory payload, never a public JSON report or signed model claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["private-model-patch-receipt-0.1.0"] = "private-model-patch-receipt-0.1.0"
    source_sha256: Digest
    finding_sha256: Digest
    context_sha256: Digest
    instructions_sha256: Digest
    answer_schema_sha256: Digest
    identity: InstructIdentity = Field(repr=False)
    generation: CompletedGeneration
    answer: PatchDraftAnswer = Field(repr=False)
    metadata: VendorDraft | None = Field(repr=False)
    candidate_text: str | None = Field(default=None, repr=False, max_length=2 * 1024**2)
    status: Literal["needs_review", "no_candidate"]
    formal_verification: Literal["not_run"] = "not_run"
    application_supported: Literal[False] = False
    automatic_activation: Literal[False] = False
    semantic_truth_proven: Literal[False] = False
    model_identity_authenticated: Literal[False] = False

    @model_validator(mode="after")
    def consistent_record(self) -> Self:
        if self.context_sha256 != self.generation.context_sha256 or (
            self.identity.source_inventory_sha256 != inventory_sha256()
            or self.identity.parameter_count != 4022468096
            or not self.identity.device_name.isprintable()
            or not 1 <= len(self.identity.runtime_versions) <= 8
            or any(
                not value.isprintable() or len(value) > 128
                for value in self.identity.runtime_versions
            )
        ):
            raise ValueError("receipt identity or observation differs")
        if self.answer.patch_draft is None:
            if (
                self.status != "no_candidate"
                or self.metadata is not None
                or self.candidate_text is not None
            ):
                raise ValueError("declined model output contains a candidate")
        elif self.status != "needs_review" or self.metadata is None or self.candidate_text is None:
            raise ValueError("candidate has no exact local review")
        elif (
            self.metadata.selected_finding_sha256 != self.finding_sha256
            or self.metadata.review.proposal.before_sha256 != self.source_sha256
            or self.metadata.review.proposal.after_sha256 != text_sha256(self.candidate_text)
        ):
            raise ValueError("candidate is not bound to the receipt")
        return self


def _bind(
    receipt: ModelPatchReceipt, prepared: PreparedPatchPrompt, expected_inventory_sha256: str
) -> ModelPatchReceipt:
    receipt = ModelPatchReceipt.model_validate(receipt.model_dump())
    if expected_inventory_sha256 != inventory_sha256() or (
        receipt.identity.source_inventory_sha256 != expected_inventory_sha256
        or receipt.source_sha256 != prepared.source_sha256
        or receipt.context_sha256 != prepared.prompt.context_sha256
        or receipt.instructions_sha256 != text_sha256(prepared.prompt.instructions)
        or receipt.answer_schema_sha256 != text_sha256(prepared.prompt.answer_schema_json)
        or receipt.finding_sha256 != json.loads(prepared.prompt.context_json)["finding"]["sha256"]
    ):
        raise ValueError("receipt binding differs")
    checked = validate_patch_answer(receipt.answer.model_dump_json().encode(), prepared)
    if receipt.metadata != checked.metadata or receipt.candidate_text != checked.candidate_text:
        raise ValueError("receipt differs from fresh local replay")
    return receipt


def create_patch_receipt(
    generated: GeneratedModelPatch,
    *,
    prepared: PreparedPatchPrompt,
    identity: InstructIdentity,
    observation: GenerationObservation,
    expected_inventory_sha256: str,
) -> ModelPatchReceipt:
    """Declared pinned identity and completed measurement; neither proves actual inference.

    Caller must capture them from its selected runtime. Artifact authentication later
    authenticates the key holder's bytes, not the GPU process or model publisher.
    """
    try:
        checked = validate_patch_answer(generated.answer.model_dump_json().encode(), prepared)
        if checked != generated:
            raise ValueError("generated candidate differs")
        receipt = ModelPatchReceipt(
            source_sha256=prepared.source_sha256,
            finding_sha256=json.loads(prepared.prompt.context_json)["finding"]["sha256"],
            context_sha256=prepared.prompt.context_sha256,
            instructions_sha256=text_sha256(prepared.prompt.instructions),
            answer_schema_sha256=text_sha256(prepared.prompt.answer_schema_json),
            identity=identity,
            generation=CompletedGeneration.model_validate(asdict(observation)),
            answer=checked.answer,
            metadata=checked.metadata,
            candidate_text=checked.candidate_text,
            status="needs_review" if checked.metadata else "no_candidate",
        )
        return _bind(receipt, prepared, expected_inventory_sha256)
    except Exception:
        raise _unavailable() from None


def _cipher(key: bytes) -> Fernet:
    if type(key) is not bytes or len(key) != 44:
        raise ValueError("unsupported receipt key")
    return Fernet(key)


def save_patch_receipt(
    receipt: ModelPatchReceipt,
    path: Path,
    *,
    key: bytes,
    prepared: PreparedPatchPrompt,
    expected_inventory_sha256: str,
) -> None:
    """One new encrypted file; no plaintext fallback, overwrite, key or source export."""
    try:
        cipher = _cipher(key)
        bound = _bind(receipt, prepared, expected_inventory_sha256)
        raw = bound.model_dump_json().encode()
        if len(raw) > MAX_PLAIN_BYTES:
            raise ValueError("receipt exceeds plaintext budget")
        safe_path(path)
        if path.suffix != ".ncp" or not path.parent.is_dir() or path.exists():
            raise ValueError("receipt target is not a new supported file")
        encrypted = _MAGIC + cipher.encrypt(raw)
        if len(encrypted) > MAX_ENCRYPTED_BYTES:
            raise ValueError("receipt exceeds encrypted budget")
        with path.open("xb") as stream:
            stream.write(encrypted)
    except Exception:
        raise _unavailable() from None


def load_patch_receipt(
    path: Path,
    *,
    key: bytes,
    prepared: PreparedPatchPrompt,
    expected_inventory_sha256: str,
) -> ModelPatchReceipt:
    """Authenticate, bound-read, decrypt and replay against caller-retained exact inputs.

    No GPU import/allocation, model generation, network or current-weight requalification.
    """
    try:
        cipher = _cipher(key)
        safe_path(path)
        if path.suffix != ".ncp" or not path.is_file() or path.stat().st_size > MAX_ENCRYPTED_BYTES:
            raise ValueError("receipt target is unsupported")
        with path.open("rb") as stream:
            encrypted = stream.read(MAX_ENCRYPTED_BYTES + 1)
        if len(encrypted) > MAX_ENCRYPTED_BYTES or not encrypted.startswith(_MAGIC):
            raise ValueError("receipt header or budget differs")
        raw = cipher.decrypt(encrypted[len(_MAGIC) :])
        if len(raw) > MAX_PLAIN_BYTES:
            raise ValueError("decrypted receipt exceeds budget")
        receipt = ModelPatchReceipt.model_validate(json.loads(raw, object_pairs_hook=_unique_keys))
        return _bind(receipt, prepared, expected_inventory_sha256)
    except Exception:
        raise _unavailable() from None
