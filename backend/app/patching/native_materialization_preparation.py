"""Fresh, side-effect-free preparation of a native candidate as an ordinary draft."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from app.api.contracts import AnalysisResult, ConfigurationSnapshot
from app.api.native_patch_contracts import NativePatchPrivate, validate_native_patch_parent
from app.api.patch_contracts import MAX_RECORD_BYTES, PatchDraft, draft_fingerprint
from app.comparison.snapshots import DiffLimitExceeded, compare_snapshots
from app.domain import CanonicalConfig
from app.ingestion.source_retention import (
    MAX_SOURCE_PAYLOAD_BYTES,
    StoredOriginalSource,
    prepare_original_source,
    validate_original_binding,
)
from app.parsers.coverage import parse_configuration_with_coverage

MAX_PREPARED_PLAINTEXT_BYTES = 16 * 1024 * 1024
CANDIDATE_FILENAME = "native-candidate.cfg"


@dataclass(frozen=True)
class PreparedNativeMaterialization:
    after: ConfigurationSnapshot
    retained_after: StoredOriginalSource = field(repr=False)
    draft: PatchDraft


def _complete(config: CanonicalConfig) -> bool:
    return (
        config.parser_confidence == 1
        and not config.parse_warnings
        and not config.unparsed_fragments
    )


def _semantics(config: CanonicalConfig) -> dict[str, Any]:
    def without_provenance(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: without_provenance(item) for key, item in value.items() if key != "provenance"
            }
        if isinstance(value, list):
            return [without_provenance(item) for item in value]
        return value

    result: dict[str, Any] = without_provenance(config.model_dump(mode="json", exclude={"source"}))
    return result


def prepare_native_materialization(
    native: NativePatchPrivate,
    before: ConfigurationSnapshot,
    analysis: AnalysisResult,
    retained_before: StoredOriginalSource,
    *,
    after_configuration_id: UUID,
    patch_id: UUID,
    created_at: datetime,
) -> PreparedNativeMaterialization:
    """Prepare fresh parser evidence and exact retained source without persisting.

    The caller must obtain retained_before explicitly. Native's private before
    copy is checked against it and is never a source-availability fallback.
    This function performs no fresh policy, model, network or generator work.
    Encryption, combined origin budgets, reservations and atomic writes belong
    to the writer, which must recheck the prepared bindings in its transaction.
    """
    native = NativePatchPrivate.model_validate_json(native.model_dump_json())
    before = ConfigurationSnapshot.model_validate_json(before.model_dump_json(), strict=True)
    analysis = AnalysisResult.model_validate_json(analysis.model_dump_json(), strict=True)
    retained_before = StoredOriginalSource.model_validate_json(
        retained_before.model_dump_json(), strict=True
    )
    validate_native_patch_parent(native.public, before, analysis)
    if (
        not isinstance(after_configuration_id, UUID)
        or not isinstance(patch_id, UUID)
        or after_configuration_id == before.configuration_id
    ):
        raise ValueError("native materialization requires distinct valid output identities")
    if created_at.utcoffset() is None or created_at < max(
        before.created_at, analysis.created_at, native.public.created_at
    ):
        raise ValueError("native materialization requires an aware current timestamp")
    if before.canonical.schema_version not in {"1.1", "1.2"} or not _complete(before.canonical):
        raise ValueError("native materialization requires a complete supported original schema")
    validate_original_binding(retained_before, before)
    if retained_before.content.encode("utf-8") != native.before_text.encode("utf-8"):
        raise ValueError("native materialization original bytes differ")
    fresh_before = prepare_original_source(before, retained_before.content)
    if fresh_before != retained_before:
        raise ValueError("native materialization retained original binding differs")

    parsed = parse_configuration_with_coverage(
        native.candidate_text,
        filename=CANDIDATE_FILENAME,
        collected_at=created_at,
        schema_version="1.2" if before.canonical.schema_version == "1.2" else "1.1",
    )
    canonical = parsed.canonical.model_copy(
        update={
            "device": parsed.canonical.device.model_copy(
                update={
                    name: getattr(before.canonical.device, name)
                    for name in ("role", "site_class", "service_profile")
                }
            )
        }
    )
    if (
        not _complete(canonical)
        or parsed.coverage.unparsed_units != 0
        or canonical.source.sha256 != native.generated_metadata.review.proposal.after_sha256
        or (canonical.device.vendor, canonical.device.platform, canonical.device.hostname)
        != (
            before.canonical.device.vendor,
            before.canonical.device.platform,
            before.canonical.device.hostname,
        )
        or before.canonical.management.telnet_enabled is not True
        or canonical.management.telnet_enabled is not False
    ):
        raise ValueError("native materialization candidate parse or identity differs")
    expected = _semantics(before.canonical)
    expected["management"]["telnet_enabled"] = False
    if _semantics(canonical) != expected:
        raise ValueError("native materialization changes unrelated normalized semantics")
    after = ConfigurationSnapshot(
        configuration_id=after_configuration_id,
        device_id=before.device_id,
        created_at=created_at,
        canonical=canonical,
        parser_coverage=parsed.coverage,
    )
    after = ConfigurationSnapshot.model_validate_json(after.model_dump_json(), strict=True)
    retained_after = prepare_original_source(after, native.candidate_text)
    diff = compare_snapshots(before, after)
    if (
        diff.coverage != "supported_complete"
        or diff.source_changed is not True
        or (diff.added_count, diff.removed_count, diff.modified_count) != (0, 0, 1)
        or len(diff.changes) != 1
    ):
        raise ValueError("native materialization requires one complete management modification")
    change = diff.changes[0]
    if (
        (change.section, change.object_key, change.kind) != ("management", ("global",), "modified")
        or change.before_value is None
        or change.after_value != {**change.before_value, "telnet_enabled": False}
        or change.before_value.get("telnet_enabled") is not True
    ):
        raise ValueError("native materialization diff differs from the expected Telnet change")
    draft = PatchDraft(
        patch_id=patch_id,
        created_at=created_at,
        diff=diff,
        draft_sha256=draft_fingerprint(diff),
    )
    draft = PatchDraft.model_validate_json(draft.model_dump_json(), strict=True)
    sizes = tuple(
        len(model.model_dump_json().encode("utf-8")) for model in (after, retained_after, draft)
    )
    if (
        sizes[1] > MAX_SOURCE_PAYLOAD_BYTES
        or sizes[2] > MAX_RECORD_BYTES
        or (sum(sizes) > MAX_PREPARED_PLAINTEXT_BYTES)
    ):
        raise DiffLimitExceeded("native materialization prepared payload exceeds budget")
    return PreparedNativeMaterialization(after=after, retained_after=retained_after, draft=draft)
