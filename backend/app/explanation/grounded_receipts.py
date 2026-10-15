"""Versioned encrypted typed answers and server projections; never approval evidence."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.explanation.grounded_patch import (
    RENDERER_VERSION,
    GeneratedGroundedPatch,
    GroundedPatchAnswer,
    GroundedSourceFacts,
    PreparedGroundedPatch,
    projection_sha256,
    renderer_policy_sha256,
    validate_grounded_patch_answer,
)
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import PatchDraftAnswer
from app.explanation.patch_receipts import (
    MAX_ENCRYPTED_BYTES,
    MAX_PLAIN_BYTES,
    CompletedGeneration,
    Digest,
    ModelPatchReceipt,
    _cipher,
)
from app.explanation.provider import _unique_keys
from app.patching.vendor_drafts import VendorDraft
from ml.inference.change_artifacts import safe_path
from ml.instruct.runtime import GenerationObservation, InstructIdentity
from ml.instruct.source import inventory_sha256

_MAGIC = b"NCS-MODEL-PATCH-2\n"


class GroundedPatchReceiptUnavailable(ValueError):
    """Diagnostics disclose no paths, source, output, keys or identity details."""


def _unavailable() -> GroundedPatchReceiptUnavailable:
    return GroundedPatchReceiptUnavailable("Grounded patch receipt is unavailable.")


class GroundedModelPatchReceipt(BaseModel):
    """The answer is a server projection, NOT the raw model wire answer."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["private-model-patch-receipt-0.2.0"] = "private-model-patch-receipt-0.2.0"
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
    model_answer: GroundedPatchAnswer = Field(repr=False)
    source_facts: GroundedSourceFacts = Field(repr=False)
    facts_binding_sha256: Digest
    model_answer_sha256: Digest
    renderer_version: Literal["grounded-before-presentation-0.1.0"] = RENDERER_VERSION
    renderer_policy_sha256: Digest
    projection_sha256: Digest

    @model_validator(mode="after")
    def validate_shared_record_constraints(self) -> Self:
        # Reuse identity/measurement/candidate structural constraints, not the old
        # prompt or receipt replay. No historical schema/instruction bytes change.
        values = self.model_dump(warnings=False)
        ModelPatchReceipt.model_validate(
            {key: values[key] for key in ModelPatchReceipt.model_fields if key != "version"}
        )
        return self

    @field_validator(
        "application_supported",
        "automatic_activation",
        "semantic_truth_proven",
        "model_identity_authenticated",
        mode="before",
    )
    @classmethod
    def exact_false(cls, value: Any) -> bool:
        if value is not False:
            raise ValueError("grounded receipt cannot assert a proved result")
        return False


def _answer_digest(answer: GroundedPatchAnswer) -> str:
    # Binds the typed raw-model object, not transport whitespace or the projection.
    return text_sha256(
        json.dumps(
            answer.model_dump(mode="json", warnings=False), sort_keys=True, separators=(",", ":")
        )
    )


def _bind(
    receipt: GroundedModelPatchReceipt,
    prepared: PreparedGroundedPatch,
    expected_inventory_sha256: str,
) -> GroundedModelPatchReceipt:
    receipt = GroundedModelPatchReceipt.model_validate(receipt.model_dump(warnings=False))
    if expected_inventory_sha256 != inventory_sha256() or (
        receipt.identity.source_inventory_sha256 != expected_inventory_sha256
        or receipt.source_sha256 != prepared.legacy.source_sha256
        or receipt.finding_sha256 != prepared.source_facts.finding_sha256
        or receipt.context_sha256 != prepared.prompt.context_sha256
        or receipt.instructions_sha256 != text_sha256(prepared.prompt.instructions)
        or receipt.answer_schema_sha256 != text_sha256(prepared.prompt.answer_schema_json)
        or receipt.source_facts != prepared.source_facts
        or receipt.facts_binding_sha256 != prepared.facts_binding_sha256
        or receipt.model_answer_sha256 != _answer_digest(receipt.model_answer)
        or receipt.renderer_version != RENDERER_VERSION
        or receipt.renderer_policy_sha256 != renderer_policy_sha256()
    ):
        raise ValueError("grounded receipt binding differs")
    replay = validate_grounded_patch_answer(
        receipt.model_answer.model_dump_json(warnings=False).encode(), prepared
    )
    checked = replay.generated
    if (
        receipt.answer != checked.answer
        or receipt.projection_sha256 != projection_sha256(checked)
        or receipt.metadata != checked.metadata
        or receipt.candidate_text != checked.candidate_text
        or receipt.status != ("needs_review" if checked.metadata else "no_candidate")
    ):
        raise ValueError("grounded receipt differs from source-bound replay")
    return receipt


def create_grounded_patch_receipt(
    generated: GeneratedGroundedPatch,
    *,
    prepared: PreparedGroundedPatch,
    identity: InstructIdentity,
    observation: GenerationObservation,
    expected_inventory_sha256: str,
) -> GroundedModelPatchReceipt:
    """Record a caller-observed new-contract generation, not a transformation of old prose.

    Neither caller measurements nor encryption authenticate a model/GPU process. The
    observation must bind the actual grounded prompt, not its legacy context component.
    """
    try:
        checked = validate_grounded_patch_answer(
            generated.model_answer.model_dump_json(warnings=False).encode(), prepared
        )
        if checked != generated:
            raise ValueError("generated grounded candidate differs")
        projection = checked.generated
        receipt = GroundedModelPatchReceipt(
            source_sha256=prepared.legacy.source_sha256,
            finding_sha256=prepared.source_facts.finding_sha256,
            context_sha256=prepared.prompt.context_sha256,
            instructions_sha256=text_sha256(prepared.prompt.instructions),
            answer_schema_sha256=text_sha256(prepared.prompt.answer_schema_json),
            identity=identity,
            generation=CompletedGeneration.model_validate(asdict(observation)),
            model_answer=checked.model_answer,
            source_facts=checked.source_facts,
            facts_binding_sha256=prepared.facts_binding_sha256,
            model_answer_sha256=_answer_digest(checked.model_answer),
            renderer_policy_sha256=renderer_policy_sha256(),
            projection_sha256=projection_sha256(projection),
            answer=projection.answer,
            metadata=projection.metadata,
            candidate_text=projection.candidate_text,
            status="needs_review" if projection.metadata else "no_candidate",
        )
        return _bind(receipt, prepared, expected_inventory_sha256)
    except Exception:
        raise _unavailable() from None


def save_grounded_patch_receipt(
    receipt: GroundedModelPatchReceipt,
    path: Path,
    *,
    key: bytes,
    prepared: PreparedGroundedPatch,
    expected_inventory_sha256: str,
) -> None:
    """Exclusive encrypted artifact; no plaintext/legacy fallback or overwrite."""
    try:
        cipher = _cipher(key)
        bound = _bind(receipt, prepared, expected_inventory_sha256)
        raw = bound.model_dump_json(warnings=False).encode()
        if len(raw) > MAX_PLAIN_BYTES:
            raise ValueError("grounded receipt exceeds plaintext budget")
        safe_path(path)
        if path.suffix != ".ncp" or not path.parent.is_dir() or path.exists():
            raise ValueError("grounded receipt target is unsupported")
        encrypted = _MAGIC + cipher.encrypt(raw)
        if len(encrypted) > MAX_ENCRYPTED_BYTES:
            raise ValueError("grounded receipt exceeds encrypted budget")
        with path.open("xb") as stream:
            stream.write(encrypted)
    except Exception:
        raise _unavailable() from None


def load_grounded_patch_receipt(
    path: Path,
    *,
    key: bytes,
    prepared: PreparedGroundedPatch,
    expected_inventory_sha256: str,
) -> GroundedModelPatchReceipt:
    """Provider-free bounded replay against caller-retained BEFORE/baseline/docs."""
    try:
        cipher = _cipher(key)
        safe_path(path)
        if path.suffix != ".ncp" or not path.is_file() or path.stat().st_size > MAX_ENCRYPTED_BYTES:
            raise ValueError("grounded receipt target is unsupported")
        with path.open("rb") as stream:
            encrypted = stream.read(MAX_ENCRYPTED_BYTES + 1)
        if len(encrypted) > MAX_ENCRYPTED_BYTES or not encrypted.startswith(_MAGIC):
            raise ValueError("grounded receipt header or budget differs")
        raw = cipher.decrypt(encrypted[len(_MAGIC) :])
        if len(raw) > MAX_PLAIN_BYTES:
            raise ValueError("grounded receipt exceeds plaintext budget")
        receipt = GroundedModelPatchReceipt.model_validate(
            json.loads(raw, object_pairs_hook=_unique_keys)
        )
        return _bind(receipt, prepared, expected_inventory_sha256)
    except Exception:
        raise _unavailable() from None
