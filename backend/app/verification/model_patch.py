"""Bind an untrusted model candidate to one exact device in explicit snapshots.

This separate scoped report never rewrites the historical draft's preflight,
authenticates model execution, grants approval, or activates an HTTP workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.fingerprints import finding_fingerprint
from app.explanation.patch_provider import (
    GeneratedModelPatch,
    PreparedPatchPrompt,
    validate_patch_answer,
)
from app.verification.batfish import BatfishResult, ReachabilityScope, check_with_batfish
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot, validate_snapshot_pair

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ModelPatchVerificationUnavailable(ValueError):
    """Constant diagnostic, without source, model output, identity, or paths."""


@dataclass(frozen=True)
class ModelPatchSnapshots:
    device_id: UUID
    before: NetworkSnapshot = field(repr=False)
    after: NetworkSnapshot = field(repr=False)


class ModelPatchBatfishReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["model-patch-batfish-0.1.0"] = "model-patch-batfish-0.1.0"
    device_id: UUID
    source_sha256: Digest
    candidate_sha256: Digest
    finding_sha256: Digest
    context_sha256: Digest
    batfish: BatfishResult
    status: Literal["needs_review"] = "needs_review"
    requires_human_review: Literal[True] = True
    approved: Literal[False] = False
    application_supported: Literal[False] = False
    device_syntax_verified: Literal[False] = False
    management_access_verified: Literal[False] = False
    model_execution_authenticated: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Only the supplied candidate replaces its exact source; other devices are preserved.",
        "The IPv4 data-plane query is not SSH access, protocol security, or vendor syntax proof.",
        "Topology completeness, rollback, ML quality and engineer approval remain unverified.",
        "Replaying a declared answer does not prove model execution or semantic truth.",
        "No historical draft status, API activation, device connection or application is changed.",
        "Device identifiers and binding hashes can still be confidential.",
    )

    @field_validator(
        "requires_human_review",
        "approved",
        "application_supported",
        "device_syntax_verified",
        "management_access_verified",
        "model_execution_authenticated",
        mode="before",
    )
    @classmethod
    def exact_flags(cls, value: Any) -> bool:
        if type(value) is not bool:
            raise ValueError("report flags must be booleans")
        return value


def prepare_model_patch_snapshots(
    generated: GeneratedModelPatch,
    *,
    prepared: PreparedPatchPrompt,
    before: NetworkSnapshot,
) -> ModelPatchSnapshots:
    """Fresh local answer/source replay; no generation, disk writes or upload consent.

    The complete network must be supplied as it existed before generation. Never
    attach topology to an already generated answer for a different minimal source.
    """
    try:
        checked = validate_patch_answer(generated.answer.model_dump_json().encode(), prepared)
        if checked != generated or checked.candidate_text is None or checked.metadata is None:
            raise ValueError("candidate is absent or differs from fresh replay")
        validate_snapshot_pair(before, before)
        device_id = prepared.finding.device_id
        selected = next((item for item in before.configs if item.device_id == device_id), None)
        if selected is None or selected.text != prepared.before:
            raise ValueError("network source differs from the exact prepared model source")
        after = prepare_snapshot(
            {
                item.device_id: checked.candidate_text if item.device_id == device_id else item.text
                for item in before.configs
            }
        )
        validate_snapshot_pair(before, after)
        return ModelPatchSnapshots(device_id, before, after)
    except Exception:
        raise ModelPatchVerificationUnavailable(
            "Model patch verification is unavailable."
        ) from None


def check_model_patch_with_batfish(
    generated: GeneratedModelPatch,
    *,
    prepared: PreparedPatchPrompt,
    before: NetworkSnapshot,
    scope: ReachabilityScope,
    allow_local_upload: bool = False,
    timeout_seconds: int = 60,
) -> ModelPatchBatfishReport:
    """Only an explicit caller opt-in can upload to the fixed loopback engine.

    Unavailable/error/empty/difference/no-difference outcomes are all retained;
    no outcome promotes the candidate or changes its existing local review.
    """
    pair = prepare_model_patch_snapshots(generated, prepared=prepared, before=before)
    try:
        scope = ReachabilityScope.model_validate(scope.model_dump())
        result = check_with_batfish(
            pair.before,
            pair.after,
            scope,
            allow_local_upload=allow_local_upload,
            timeout_seconds=timeout_seconds,
        )
        result = BatfishResult.model_validate(result.model_dump())
        if (
            result.before_sha256 != pair.before.digest
            or result.after_sha256 != pair.after.digest
            or result.scope != scope
        ):
            raise ValueError("engine result binding differs")
        return ModelPatchBatfishReport(
            device_id=pair.device_id,
            source_sha256=prepared.source_sha256,
            candidate_sha256=next(
                item.digest for item in pair.after.configs if item.device_id == pair.device_id
            ),
            finding_sha256=finding_fingerprint(prepared.finding),
            context_sha256=prepared.prompt.context_sha256,
            batfish=result,
        )
    except Exception:
        raise ModelPatchVerificationUnavailable(
            "Model patch verification is unavailable."
        ) from None
