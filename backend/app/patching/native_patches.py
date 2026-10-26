"""Explicit retained-source native generation, followed by immutable private history."""

from datetime import UTC, datetime
from uuid import UUID

from pydantic import ValidationError

from app.api.native_patch_contracts import (
    GenerateNativePatch,
    NativePatchBudgetError,
    NativePatchCandidate,
    NativePatchPrivate,
    NativePatchSelection,
    native_patch_candidate,
    native_patch_selection,
)
from app.core.permissions import Role
from app.db.native_patch_records import (
    NativePatchInputNotFound,
    NativePatchRecords,
    NativePatchTooLarge,
)
from app.db.patch_records import PatchConflict
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.detection.policy_engine import evaluate_policies
from app.domain.fingerprints import finding_fingerprint
from app.ingestion.source_retention import prepare_original_source
from app.patching.vendor_drafts import create_vendor_draft


class NativePatchWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.records = NativePatchRecords(store)

    def selection(self, configuration_id: UUID, analysis_id: UUID) -> NativePatchSelection:
        snapshot = self.store.get_configuration(configuration_id)
        analysis = self.store.get_analysis(analysis_id)
        if snapshot is None or analysis is None:
            raise NativePatchInputNotFound()
        try:
            return native_patch_selection(snapshot, analysis)
        except ValueError:
            raise PatchConflict("Selected analysis is incompatible.") from None

    def get(self, configuration_id: UUID, candidate_id: UUID) -> NativePatchCandidate:
        saved = self.records.get(candidate_id)
        if saved is None or saved.public.configuration_id != configuration_id:
            raise NativePatchInputNotFound()
        return saved.public

    def create(
        self,
        configuration_id: UUID,
        options: GenerateNativePatch,
        service_role: Role,
    ) -> tuple[NativePatchCandidate, bool]:
        options = GenerateNativePatch.model_validate_json(options.model_dump_json())
        # Replay must precede retained-source access or any fresh runtime evaluation.
        existing = self.records.get(options.candidate_id)
        if existing is not None:
            if existing.public.configuration_id != configuration_id or (
                existing.public.request != options
            ):
                raise PatchConflict("Saved native candidate identity conflicts.")
            return existing.public, False
        if service_role != "engineer" and service_role != "admin":
            raise PatchConflict("Native generation requires the drafting service role.")
        snapshot = self.store.get_configuration(configuration_id)
        analysis = self.store.get_analysis(options.analysis_id)
        if snapshot is None or analysis is None:
            raise NativePatchInputNotFound()
        try:
            selection = native_patch_selection(snapshot, analysis)
            if (
                options.analysis_sha256 != selection.analysis_sha256
                or options.source_sha256 != selection.source.source_sha256
                or options.canonical_sha256 != selection.canonical_sha256
                or options.policy_catalog_version != selection.policy_catalog_version
            ):
                raise ValueError("stale selection")
            selected = [row for row in analysis.findings if row.finding_id == options.finding_id]
            if len(selected) != 1:
                raise ValueError("missing or duplicate finding")
            finding = selected[0]
            if (
                finding.category != "management.telnet_enabled"
                or finding.detector != "policy_engine"
                or finding_fingerprint(finding) != options.finding_sha256
            ):
                raise ValueError("unsupported selection")
            retained = SourceRecords(self.store).get(
                configuration_id,
                expected_source_sha256=options.source_sha256,
                allow_local_read=options.allow_local_native_generation,
            )
            if len(retained.content.encode("utf-8")) > 2 * 1024 * 1024:
                raise NativePatchTooLarge()
            original = prepare_original_source(snapshot, retained.content)
            # Reparse admission above binds the exact bytes to the saved canonical form.
            saved_policy = [row for row in analysis.findings if row.detector == "policy_engine"]
            fresh_policy = evaluate_policies(snapshot.canonical, device_id=analysis.device_id)
            saved_map = {row.finding_id: finding_fingerprint(row) for row in saved_policy}
            fresh_map = {row.finding_id: finding_fingerprint(row) for row in fresh_policy}
            if len(saved_map) != len(saved_policy) or saved_map != fresh_map:
                raise ValueError("policy findings differ")
            generated = create_vendor_draft(
                original.content,
                finding=finding,
                source_sha256=options.source_sha256,
                reference_id=str(configuration_id),
            )
            public = native_patch_candidate(
                configuration_id,
                options,
                snapshot,
                analysis,
                generated.metadata,
                created_at=datetime.now(UTC),
                service_role=service_role,
            )
            private = NativePatchPrivate(
                public=public,
                generated_metadata=generated.metadata,
                before_text=original.content,
                candidate_text=generated.candidate_text,
            )
        except (NativePatchTooLarge, NativePatchBudgetError):
            raise NativePatchTooLarge() from None
        except (ValueError, OriginalSourceUnavailable) as error:
            if isinstance(error, ValidationError) and any(
                isinstance(item.get("ctx", {}).get("error"), NativePatchBudgetError)
                for item in error.errors(include_input=False)
            ):
                raise NativePatchTooLarge() from None
            raise PatchConflict("Selected retained source or finding is incompatible.") from None
        saved, created = self.records.save(private)
        return saved.public, created
