"""Explicit native candidate to ordinary draft preparation and atomic persistence."""

from datetime import UTC, datetime
from uuid import UUID

from pydantic import ValidationError

from app.api.native_materialization_contracts import (
    CreateNativeMaterialization,
    NativeMaterialization,
    NativeMaterializationBudgetError,
    native_materialization_record,
)
from app.comparison.snapshots import DiffLimitExceeded
from app.core.permissions import Role
from app.db.native_materialization_records import (
    NativeMaterializationRecords,
    NativeMaterializationTooLarge,
)
from app.db.native_patch_records import NativePatchInputNotFound, NativePatchRecords
from app.db.patch_records import PatchConflict
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.patching.native_materialization_preparation import prepare_native_materialization


class NativeMaterializationWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.records = NativeMaterializationRecords(store)

    @staticmethod
    def _intent(
        saved: NativeMaterialization,
        configuration_id: UUID,
        options: CreateNativeMaterialization,
    ) -> None:
        if saved.configuration_id != configuration_id or saved.request != options:
            raise PatchConflict("Saved native materialization intent conflicts.")

    def get(self, configuration_id: UUID, candidate_id: UUID) -> NativeMaterialization:
        saved = self.records.get(candidate_id)
        if saved is None or saved.configuration_id != configuration_id:
            raise NativePatchInputNotFound()
        return saved

    def origin(self, after_configuration_id: UUID) -> NativeMaterialization:
        saved = self.records.get_origin(after_configuration_id)
        if saved is None:
            raise NativePatchInputNotFound()
        return saved

    def create(
        self,
        configuration_id: UUID,
        candidate_id: UUID,
        options: CreateNativeMaterialization,
        service_role: Role,
    ) -> tuple[NativeMaterialization, bool]:
        options = CreateNativeMaterialization.model_validate_json(options.model_dump_json())
        # Historical replay must precede source access, parser admission and new output creation.
        existing = self.records.get(candidate_id)
        if existing is not None:
            self._intent(existing, configuration_id, options)
            return existing, False
        if service_role != "engineer" and service_role != "admin":
            raise PatchConflict("Native materialization requires the drafting service role.")
        native = NativePatchRecords(self.store).get(candidate_id)
        if native is None:
            raise NativePatchInputNotFound()
        if native.public.configuration_id != configuration_id:
            raise PatchConflict("Selected native candidate URL conflicts.")
        before = self.store.get_configuration(configuration_id)
        analysis = self.store.get_analysis(native.public.request.analysis_id)
        if before is None or analysis is None:
            raise NativePatchInputNotFound()
        if options.native_review_sha256 != native.public.review_sha256:
            raise PatchConflict("Selected native candidate proof conflicts.")
        try:
            retained_before = SourceRecords(self.store).get(
                configuration_id,
                expected_source_sha256=native.public.source.source_sha256,
                allow_local_read=options.allow_local_source_materialization,
            )
            created_at = datetime.now(UTC)
            prepared = prepare_native_materialization(
                native,
                before,
                analysis,
                retained_before,
                after_configuration_id=options.after_configuration_id,
                patch_id=options.patch_id,
                created_at=created_at,
            )
            record = native_materialization_record(
                configuration_id,
                candidate_id,
                options,
                native,
                before,
                prepared,
                created_at=created_at,
                service_role=service_role,
            )
        except (NativeMaterializationBudgetError, DiffLimitExceeded):
            raise NativeMaterializationTooLarge() from None
        except (ValueError, OriginalSourceUnavailable) as error:
            if isinstance(error, ValidationError) and any(
                isinstance(item.get("ctx", {}).get("error"), NativeMaterializationBudgetError)
                for item in error.errors(include_input=False)
            ):
                raise NativeMaterializationTooLarge() from None
            raise PatchConflict("Selected source or native candidate is incompatible.") from None
        return self.records.save(record, prepared, retained_before)
