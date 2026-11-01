"""Immutable generated-origin proof for an explicitly materialized native candidate."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator, model_validator

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.api.native_patch_contracts import Digest, NativePatchPrivate
from app.api.patch_contracts import PatchDraft
from app.comparison.snapshots import compare_snapshots
from app.ingestion.source_retention import canonical_fingerprint

if TYPE_CHECKING:
    from app.patching.native_materialization_preparation import PreparedNativeMaterialization

MAX_NATIVE_MATERIALIZATION_REVIEW_BYTES = 512 * 1024
MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES = 1024 * 1024
MAX_NATIVE_MATERIALIZATION_CIPHERTEXT_BYTES = 2 * 1024 * 1024


class NativeMaterializationBudgetError(ValueError):
    """A new generated-origin proof exceeds its versioned budget."""


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


class _FrozenMaterialization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def untrust_instances(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="python")
        return value


class CreateNativeMaterialization(_FrozenMaterialization):
    version: Literal["native-materialization-request-0.1.0"]
    after_configuration_id: UUID
    patch_id: UUID
    native_review_sha256: Digest
    allow_local_source_materialization: Literal[True]
    allow_private_candidate_source_retention: Literal[True]

    @field_validator(
        "allow_local_source_materialization",
        "allow_private_candidate_source_retention",
        mode="before",
    )
    @classmethod
    def exact_consent(cls, value: Any) -> Any:
        if value is not True:
            raise ValueError("materialization requires exact true consent")
        return value


class NativeMaterialization(_FrozenMaterialization):
    version: Literal["native-materialization-0.1.0"] = "native-materialization-0.1.0"
    candidate_id: UUID
    configuration_id: UUID
    request: CreateNativeMaterialization
    native_review_sha256: Digest
    created_at: AwareDatetime
    service_role: Literal["engineer", "admin"]
    before: SnapshotBinding
    after: SnapshotBinding
    after_canonical_sha256: Digest
    patch_id: UUID
    draft_sha256: Digest
    representation: Literal["normalized_objects"] = "normalized_objects"
    origin: Literal["generated_native_candidate"] = "generated_native_candidate"
    status: Literal["draft_created"] = "draft_created"
    formal_qualification: Literal["not_proven"] = "not_proven"
    fresh_policy_recheck_performed: Literal[False] = False
    model_recheck_performed: Literal[False] = False
    network_verification_performed: Literal[False] = False
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    review_json: str
    review_sha256: Digest

    @field_validator(
        "fresh_policy_recheck_performed",
        "model_recheck_performed",
        "network_verification_performed",
        "individual_identity_verified",
        "approved",
        "applied",
        mode="before",
    )
    @classmethod
    def exact_false(cls, value: Any) -> Any:
        if value is not False:
            raise ValueError("materialization assurance flags require exact false")
        return value

    @model_validator(mode="after")
    def bound_proof(self) -> Self:
        if (
            self.configuration_id != self.before.configuration_id
            or self.after.configuration_id != self.request.after_configuration_id
            or self.patch_id != self.request.patch_id
            or self.native_review_sha256 != self.request.native_review_sha256
            or self.before.configuration_id == self.after.configuration_id
            or self.before.device_id != self.after.device_id
            or self.before.source_sha256 == self.after.source_sha256
            or self.before.created_at.utcoffset() is None
            or self.after.created_at.utcoffset() is None
            or self.before.created_at > self.created_at
            or self.after.created_at != self.created_at
        ):
            raise ValueError("materialization bindings differ")
        body = self.model_dump(mode="json", exclude={"review_json", "review_sha256"})
        encoded = _json(body)
        if len(encoded.encode("utf-8")) > MAX_NATIVE_MATERIALIZATION_REVIEW_BYTES:
            raise NativeMaterializationBudgetError("materialization proof exceeds budget")
        if (
            self.review_json != encoded
            or self.review_sha256 != sha256(encoded.encode()).hexdigest()
        ):
            raise ValueError("materialization proof differs")
        if len(self.model_dump_json().encode()) > MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES:
            raise NativeMaterializationBudgetError("materialization payload exceeds budget")
        return self


def validate_native_materialization_parent(
    record: NativeMaterialization,
    native: NativePatchPrivate,
    before: ConfigurationSnapshot,
    after: ConfigurationSnapshot,
    draft: PatchDraft,
) -> None:
    """Check saved data only; no source reads, parser, policy or generator execution."""
    record = NativeMaterialization.model_validate_json(record.model_dump_json())
    native = NativePatchPrivate.model_validate_json(native.model_dump_json())
    before = ConfigurationSnapshot.model_validate_json(before.model_dump_json(), strict=True)
    after = ConfigurationSnapshot.model_validate_json(after.model_dump_json(), strict=True)
    raw_draft = draft.model_dump(mode="python")
    if raw_draft.get("requires_human_review") is not True or (
        isinstance(raw_draft.get("diff"), Mapping)
        and raw_draft["diff"].get("source_changed") is not True
    ):
        raise ValueError("materialization draft flags differ")
    draft = PatchDraft.model_validate_json(draft.model_dump_json(), strict=True)
    if (
        record.candidate_id != native.public.candidate_id
        or record.configuration_id != native.public.configuration_id
        or record.native_review_sha256 != native.public.review_sha256
        or record.before != native.public.source
        or record.before != SnapshotBinding.from_snapshot(before)
        or record.after != SnapshotBinding.from_snapshot(after)
        or record.after_canonical_sha256 != canonical_fingerprint(after)
        or record.after.source_sha256 != native.generated_metadata.review.proposal.after_sha256
        or record.created_at < max(native.public.created_at, native.public.analysis_created_at)
        or record.patch_id != draft.patch_id
        or record.draft_sha256 != draft.draft_sha256
        or record.created_at != draft.created_at
        or draft.diff != compare_snapshots(before, after)
    ):
        raise ValueError("materialization differs from saved parents")

    # Keep the exact normalized mutation invariant independently of current parser code.
    def semantics(snapshot: ConfigurationSnapshot) -> Any:
        def strip(value: Any) -> Any:
            if isinstance(value, dict):
                return {key: strip(item) for key, item in value.items() if key != "provenance"}
            if isinstance(value, list):
                return [strip(item) for item in value]
            return value

        return strip(snapshot.canonical.model_dump(mode="json", exclude={"source"}))

    expected = semantics(before)
    expected["management"]["telnet_enabled"] = False
    if (
        before.canonical.management.telnet_enabled is not True
        or after.canonical.management.telnet_enabled is not False
        or semantics(after) != expected
        or after.canonical.schema_version not in {"1.1", "1.2"}
        or after.canonical.parser_confidence != 1
        or after.canonical.parse_warnings
        or after.canonical.unparsed_fragments
        or after.parser_coverage is None
        or after.parser_coverage.unparsed_units != 0
        or draft.diff.coverage != "supported_complete"
        or (draft.diff.added_count, draft.diff.removed_count, draft.diff.modified_count)
        != (0, 0, 1)
    ):
        raise ValueError("materialization normalized mutation differs")


def native_materialization_record(
    configuration_id: UUID,
    candidate_id: UUID,
    options: CreateNativeMaterialization,
    native: NativePatchPrivate,
    before: ConfigurationSnapshot,
    prepared: PreparedNativeMaterialization,
    *,
    created_at: datetime,
    service_role: Literal["engineer", "admin"],
) -> NativeMaterialization:
    options = CreateNativeMaterialization.model_validate(options)
    body = NativeMaterialization.model_construct(
        candidate_id=candidate_id,
        configuration_id=configuration_id,
        request=options,
        native_review_sha256=options.native_review_sha256,
        created_at=created_at,
        service_role=service_role,
        before=SnapshotBinding.from_snapshot(before),
        after=SnapshotBinding.from_snapshot(prepared.after),
        after_canonical_sha256=canonical_fingerprint(prepared.after),
        patch_id=prepared.draft.patch_id,
        draft_sha256=prepared.draft.draft_sha256,
        review_json="",
        review_sha256="0" * 64,
    ).model_dump(mode="json", exclude={"review_json", "review_sha256"})
    encoded = _json(body)
    result = NativeMaterialization.model_validate(
        {**body, "review_json": encoded, "review_sha256": sha256(encoded.encode()).hexdigest()}
    )
    validate_native_materialization_parent(result, native, before, prepared.after, prepared.draft)
    return result
